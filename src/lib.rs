//! This is a Rust REST client library for calling the Bitcoin Core REST API. It
//! makes it easy to talk to the Bitcoin Core REST interface.
//!
//! The REST interface is useful for quickly iterating over the blockchain, because
//! it can request blocks and transactions in binary form without having to
//! serialize/deserialize into JSON. It is unauthenticated so there's no need to
//! worry about storing credentials.
//!
//! It also has API for quickly retrieving large amounts of block headers and BIP157
//! compact block filter headers. There is also support for getting block chain
//! info, mempool info, the raw mempool, and querying the utxo set.
//!
//! See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md>
//! for more information.
use bitcoin::consensus::encode::{deserialize, Decodable, ReadExt};
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::amount::serde::as_btc;
use bitcoin::util::bip158::BlockFilter;
use bitcoin::{
    Amount, Block, BlockHash, BlockHeader, FilterHeader, Network, OutPoint, Transaction, TxOut,
    Txid, VarInt,
};
use bitcoincore_rpc_json::{GetBlockchainInfoResult, GetMempoolEntryResult};
use bytes::Bytes;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read};

const BLOCK_HEADER_SIZE: usize = 80usize;
const BLOCK_FILTER_HEADER_SIZE: usize = 32usize;

/// Creates HTTP requests to bitcoind
#[derive(Clone)]
pub struct BitcoinRest {
    client: Client,
    endpoint: String,
}

/// Response from `get_mempool_info`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolInfoResult {
    pub loaded: bool,
    pub size: u64,
    pub bytes: u64,
    pub usage: u64,
    #[serde(with = "as_btc")]
    pub total_fee: Amount,
    #[serde(rename = "maxmempool")]
    pub max_mempool: u64,
    #[serde(rename = "mempoolminfee", with = "as_btc")]
    pub mempool_min_fee: Amount,
    #[serde(rename = "minrelaytxfee", with = "as_btc")]
    pub min_relay_tx_fee: Amount,
    #[serde(rename = "unbroadcastcount")]
    pub unbroadcast_count: u64,
    #[serde(rename = "fullrbf")]
    pub full_rbf: Option<bool>,
}

/// Sub object containing height and output from `get_utxos`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Utxo {
    pub height: i32,
    pub output: TxOut,
}

/// Response from `get_utxos`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GetUtxosResult {
    pub chain_height: u32,
    pub chain_tip_hash: BlockHash,
    pub bitmap: Vec<u8>,
    pub utxos: Vec<Utxo>,
}

#[derive(Debug)]
pub enum Error {
    NotFoundError,
    ReqwestError(reqwest::Error),
    BitcoinEncodeError(bitcoin::consensus::encode::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::NotFoundError => write!(f, "Not found"),
            Error::ReqwestError(ref e) => write!(f, "Reqwest error, {}", e),
            Error::BitcoinEncodeError(ref e) => write!(f, "Bitcoin encode error, {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            NotFoundError => None,
            ReqwestError(e) => Some(e),
            BitcoinEncodeError(e) => Some(e),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::ReqwestError(err)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        Self::BitcoinEncodeError(err)
    }
}

fn read_bytes(reader: &mut impl Read, num: usize) -> Result<Vec<u8>, Error> {
    let mut ret = Vec::with_capacity(num);
    for _ in 0..num {
        ret.push(reader.read_u8()?);
    }
    Ok(ret)
}

fn decode_utxos_result(reader: &mut impl Read) -> Result<GetUtxosResult, Error> {
    let chain_height: u32 = Decodable::consensus_decode_from_finite_reader(reader)?;
    let chain_tip_hash: BlockHash = Decodable::consensus_decode_from_finite_reader(reader)?;
    let bitmap_byte_count: VarInt = Decodable::consensus_decode_from_finite_reader(reader)?;
    let bitmap: Vec<u8> = read_bytes(reader, bitmap_byte_count.0 as usize)?;

    let utxo_count: VarInt = Decodable::consensus_decode_from_finite_reader(reader)?;

    let mut utxos = Vec::with_capacity(utxo_count.0 as usize);
    for _ in 0..utxo_count.0 {
        let utxo = decode_utxo(reader)?;
        utxos.push(utxo);
    }

    Ok(GetUtxosResult {
        chain_height,
        chain_tip_hash,
        bitmap,
        utxos,
    })
}

fn decode_utxo(reader: &mut impl Read) -> Result<Utxo, Error> {
    // Unknown 4 bytes of zero data at start of utxo
    let _: [u8; 4] = Decodable::consensus_decode_from_finite_reader(reader)?;
    Ok(Utxo {
        height: Decodable::consensus_decode_from_finite_reader(reader)?,
        output: Decodable::consensus_decode_from_finite_reader(reader)?,
    })
}

impl BitcoinRest {
    /// Create a new `BitcoinRest` instance with given endpoint url
    ///
    /// Must be in the format `"http://{ip}:{port}/rest/"`
    pub fn new(endpoint: String) -> Self {
        BitcoinRest {
            client: Client::new(),
            endpoint,
        }
    }

    /// Create a new `BitcoinRest` instance with the default endpoint for that network
    ///
    /// For example, [`Network::Bitcoin`] creates an instance with `"http://localhost:8332/rest/"`
    pub fn network_default(network: Network) -> Self {
        let endpoint = match network {
            Network::Bitcoin => "http://localhost:8332/rest/",
            Network::Testnet => "http://localhost:18332/rest/",
            Network::Signet => "http://localhost:38332/rest/",
            Network::Regtest => "http://localhost:18443/rest/",
        };

        BitcoinRest {
            client: Client::new(),
            endpoint: endpoint.to_string(),
        }
    }

    /// Get a response from a `json` endpoint
    pub async fn get_json<T: for<'a> Deserialize<'a>>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}{}.json", &self.endpoint, path);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(Error::NotFoundError);
        }

        response
            .json::<T>()
            .await
            .map_err(|e| Error::ReqwestError(e))
    }

    /// Get a response from a `bin` endpoint
    pub async fn get_bin(&self, path: &str) -> Result<Bytes, Error> {
        let url = format!("{}{}.bin", &self.endpoint, path);
        let response = self.client.get(&url).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(Error::NotFoundError);
        }

        response.bytes().await.map_err(|e| Error::ReqwestError(e))
    }

    /// Get a series of block headers beginning from a block hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockheaders>
    pub async fn get_block_headers(
        &self,
        start_hash: &BlockHash,
        count: u32,
    ) -> Result<Vec<BlockHeader>, Error> {
        let path = &["headers", &count.to_string(), &start_hash.to_string()].join("/");
        let resp = self.get_bin(path).await?;

        let mut vec = Vec::<BlockHeader>::with_capacity(resp.len() / BLOCK_HEADER_SIZE);
        let mut offset = 0;
        while offset < resp.len() {
            vec.push(deserialize(&resp[offset..(offset + BLOCK_HEADER_SIZE)])?);
            offset += BLOCK_HEADER_SIZE;
        }
        Ok(vec)
    }

    /// Convenience function to get a block at a specific height
    pub async fn get_block_at_height(&self, height: u64) -> Result<Block, Error> {
        let hash = self.get_block_hash(height).await?;
        self.get_block(&hash).await
    }

    /// Get a block hash at a specific height
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockhash-by-height>
    pub async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        let path = &["blockhashbyheight", &height.to_string()].join("/");
        let resp = self.get_bin(path).await?;
        Ok(deserialize(&resp)?)
    }

    /// Get a block by its hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blocks>
    pub async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        let path = &["block", &hash.to_hex()].join("/");
        let resp = self.get_bin(path).await?;
        Ok(deserialize(&resp)?)
    }

    /// Get a transaction by its `txid`
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#transactions>
    pub async fn get_transaction(&self, txid: &Txid) -> Result<Transaction, Error> {
        let path = &["tx", &txid.to_hex()].join("/");
        let resp = self.get_bin(path).await?;
        Ok(deserialize(&resp)?)
    }

    /// Get a series of block filter headers beginning from a block hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockfilter-headers>
    pub async fn get_block_filter_headers(
        &self,
        start_hash: &BlockHash,
        count: u32,
    ) -> Result<Vec<FilterHeader>, Error> {
        let path = &[
            "blockfilterheaders",
            "basic",
            &count.to_string(),
            &start_hash.to_hex(),
        ]
        .join("/");
        let resp = self.get_bin(path).await?;

        let mut vec = Vec::<FilterHeader>::with_capacity(resp.len() / BLOCK_FILTER_HEADER_SIZE);
        let mut offset = 0;
        while offset < resp.len() {
            vec.push(deserialize(
                &resp[offset..(offset + BLOCK_FILTER_HEADER_SIZE)],
            )?);
            offset += BLOCK_FILTER_HEADER_SIZE;
        }
        Ok(vec)
    }

    /// Get a block filter for a given block hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockfilters>
    pub async fn get_block_filter(&self, hash: &BlockHash) -> Result<BlockFilter, Error> {
        let path = &["blockfilter", "basic", &hash.to_hex()].join("/");
        let resp = self.get_bin(path).await?;
        let mut contents: Vec<u8> = vec![];
        let mut cursor = Cursor::new(&resp);
        cursor
            .read_to_end(&mut contents)
            .map_err(|e| Error::BitcoinEncodeError(bitcoin::consensus::encode::Error::Io(e)))?;
        Ok(BlockFilter::new(&contents))
    }

    /// Get info on the block chain state
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#chaininfos>
    pub async fn get_chain_info(&self) -> Result<GetBlockchainInfoResult, Error> {
        let path = "chaininfo";
        self.get_json(path).await
    }

    /// Get utxos for a given set of outpoints
    ///
    /// Optionally check unconfirmed utxos in the mempool
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#query-utxo-set>
    pub async fn get_utxos(
        &self,
        outpoints: Vec<OutPoint>,
        check_mempool: bool,
    ) -> Result<GetUtxosResult, Error> {
        let mut path = Vec::with_capacity(1 + if check_mempool { 1 } else { 0 } + outpoints.len());
        path.push("getutxos".to_string());
        if check_mempool {
            path.push("checkmempool".to_string());
        }
        for outpoint in outpoints {
            path.push([outpoint.txid.to_string(), outpoint.vout.to_string()].join("-"));
        }
        let resp = self.get_bin(&path.join("/")).await?;

        let mut cursor = Cursor::new(&resp);
        Ok(decode_utxos_result(&mut cursor)?)
    }

    /// Get info on the mempool state
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#memory-pool>
    pub async fn get_mempool_info(&self) -> Result<GetMempoolInfoResult, Error> {
        let path = "mempool/info";
        self.get_json(path).await
    }

    /// Get info for every transaction in the mempool
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#memory-pool>
    pub async fn get_mempool(&self) -> Result<HashMap<Txid, GetMempoolEntryResult>, Error> {
        let path = "mempool/contents";
        self.get_json(path).await
    }
}

#[cfg(test)]
mod tests {

    use super::BitcoinRest;
    use super::Error;

    use anyhow::Result;
    use bitcoin::{Amount, OutPoint};
    use bitcoincore_rpc::RpcApi;
    use bitcoind::{downloaded_exe_path, BitcoinD, Conf};
    use env_logger;

    const NUM_BLOCKS: u32 = 101;

    #[tokio::test]
    async fn test_rest() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut conf = Conf::default();
        conf.args = vec![
            "-rest",
            "-blockfilterindex",
            "-regtest",
            "-fallbackfee=0.0001",
        ];
        let bitcoind = BitcoinD::with_conf(downloaded_exe_path()?, &conf)?;
        let address = bitcoind.client.get_new_address(None, None)?;
        bitcoind
            .client
            .generate_to_address(NUM_BLOCKS as u64, &address)?;

        let rpc_socket = bitcoind.params.rpc_socket;

        let bitcoin_rest = BitcoinRest::new(format!("http://{}/rest/", rpc_socket.to_string()));

        let hash = bitcoin_rest.get_block_hash(NUM_BLOCKS as u64).await?;
        assert_eq!(hash, bitcoind.client.get_block_hash(NUM_BLOCKS as u64)?);

        let block = bitcoin_rest.get_block_at_height(NUM_BLOCKS as u64).await?;
        assert_eq!(block, bitcoind.client.get_block(&hash)?);
        assert_eq!(block, bitcoin_rest.get_block(&hash).await?);

        let first_hash = bitcoin_rest.get_block_hash(0).await?;
        let headers = bitcoin_rest
            .get_block_headers(&first_hash, NUM_BLOCKS)
            .await?;
        assert_eq!(headers.len(), NUM_BLOCKS as usize);
        assert_eq!(headers[1].prev_blockhash, first_hash);

        let filter_headers = bitcoin_rest
            .get_block_filter_headers(&first_hash, NUM_BLOCKS)
            .await?;
        assert_eq!(filter_headers.len(), NUM_BLOCKS as usize);

        let _ = bitcoin_rest.get_block_filter(&hash).await?;

        let txid = bitcoind.client.send_to_address(
            &address,
            Amount::ONE_BTC,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        let txid2 = bitcoind.client.send_to_address(
            &address,
            Amount::from_btc(0.5)?,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        let chain_info = bitcoin_rest.get_chain_info().await?;
        assert_eq!(chain_info.chain, "regtest");
        assert_eq!(chain_info.blocks, NUM_BLOCKS as u64);
        assert_eq!(chain_info.best_block_hash, hash);

        let mempool_info = bitcoin_rest.get_mempool_info().await?;
        assert_eq!(mempool_info.loaded, true);
        assert_eq!(mempool_info.size, 2);

        let mempool = bitcoin_rest.get_mempool().await?;
        assert_eq!(mempool.len(), 2);
        let entry = mempool.get(&txid);
        assert_ne!(entry, None);

        let tx = bitcoin_rest.get_transaction(&txid).await?;
        assert_eq!(tx.txid(), txid);

        let outpoints = vec![
            OutPoint::new(txid, 0),
            OutPoint::new(txid, 1),
            OutPoint::new(txid2, 0),
            OutPoint::new(txid2, 1),
        ];
        let utxo_result = bitcoin_rest.get_utxos(outpoints.clone(), true).await?;
        assert_eq!(utxo_result.chain_height, NUM_BLOCKS);
        assert_eq!(utxo_result.chain_tip_hash, hash);
        assert_eq!(utxo_result.utxos.len(), 3);
        let utxo = &utxo_result.utxos[0];
        assert_eq!(utxo.height, i32::MAX);

        bitcoind.client.generate_to_address(1, &address)?;
        let utxo_result = bitcoin_rest.get_utxos(outpoints, true).await?;
        let utxo = &utxo_result.utxos[0];
        assert_eq!(utxo.height, (NUM_BLOCKS + 1) as i32);
        let utxo = &utxo_result.utxos[1];
        if Amount::from_sat(utxo.output.value) == Amount::from_btc(0.5)? {
            assert_eq!(utxo.output.script_pubkey, address.script_pubkey());
        } else {
            let utxo = &utxo_result.utxos[2];
            assert_eq!(utxo.output.script_pubkey, address.script_pubkey());
        }

        let result = bitcoin_rest.get_block_hash((NUM_BLOCKS + 2) as u64).await;
        match result {
            Err(Error::NotFoundError) => {}
            Err(_) => assert!(false),
            Ok(_) => assert!(false),
        }

        Ok(())
    }
}
