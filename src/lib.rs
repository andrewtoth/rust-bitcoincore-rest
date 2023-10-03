//! A Rust REST client library for calling the Bitcoin Core REST API. It
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
use std::{
    collections::HashMap,
    io::{Cursor, Read},
};

pub mod responses;

use crate::responses::{
    deployment_info::GetDeploymentInfoResult,
    get_utxos::{GetUtxosResult, Utxo},
    GetMempoolTxidsAndSequenceResult,
};

use async_trait::async_trait;
use bitcoin::{
    bip158::BlockFilter,
    block::Header,
    consensus::encode::{deserialize, Decodable, ReadExt},
    hash_types::FilterHeader,
    Block, BlockHash, Network, OutPoint, Transaction, Txid, VarInt,
};
use bitcoincore_rpc_json::{GetBlockchainInfoResult, GetMempoolEntryResult, GetMempoolInfoResult};
use bytes::Bytes;
use http::StatusCode;
#[cfg(feature = "use-reqwest")]
use reqwest::{Client, IntoUrl};
use serde::Deserialize;
#[cfg(feature = "use-reqwest")]
use url::Url;

pub use bitcoin;
pub use bitcoincore_rpc_json;
pub use bytes;
pub use http;
pub use serde;

/// Error type for RestApi responses.
#[derive(Debug)]
pub enum Error {
    BitcoinEncodeError(bitcoin::consensus::encode::Error),
    NotOkError(StatusCode),
    #[cfg(feature = "use-reqwest")]
    ReqwestError(reqwest::Error),
    #[cfg(not(feature = "use-reqwest"))]
    CustomError(Box<dyn std::error::Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::BitcoinEncodeError(ref e) => write!(f, "Bitcoin encode error, {e}"),
            Error::NotOkError(ref e) => write!(f, "Incorrect status code {e}"),
            #[cfg(feature = "use-reqwest")]
            Error::ReqwestError(ref e) => write!(f, "Reqwest error, {e}"),
            #[cfg(not(feature = "use-reqwest"))]
            Error::CustomError(ref e) => write!(f, "Custom error, {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            BitcoinEncodeError(e) => Some(e),
            NotOkError(_) => None,
            #[cfg(feature = "use-reqwest")]
            ReqwestError(e) => Some(e),
            #[cfg(not(feature = "use-reqwest"))]
            CustomError(e) => Some(e.as_ref()),
        }
    }
}

#[cfg(feature = "use-reqwest")]
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

/// Implements all the REST API calls for Bitcoin Core, except
/// [`get_json`](RestApi::get_json) and [`get_bin`](RestApi::get_bin).
///
/// These are implemented using [`reqwest`](reqwest) in
/// [`RestClient`](RestClient), but this dependency can be removed by using
/// `default-features = false` in `Cargo.toml` and implementing `RestApi`
/// yourself.
#[async_trait]
pub trait RestApi {
    /// Get a response from a `json` endpoint
    async fn get_json<T: for<'a> Deserialize<'a>>(&self, path: &str) -> Result<T, Error>;

    /// Get a response from a `bin` endpoint
    async fn get_bin(&self, path: &str) -> Result<Bytes, Error>;

    /// Get a series of block headers beginning from a block hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockheaders>
    async fn get_block_headers(
        &self,
        start_hash: BlockHash,
        count: u32,
    ) -> Result<Vec<Header>, Error> {
        let path = format!("rest/headers/{count}/{start_hash}.bin",);
        let resp = self.get_bin(&path).await?;

        const BLOCK_HEADER_SIZE: usize = 80usize;
        let num = resp.len() / BLOCK_HEADER_SIZE;
        let mut vec = Vec::<Header>::with_capacity(num);
        let mut decoder = Cursor::new(resp);
        for _ in 0..num {
            vec.push(Header::consensus_decode_from_finite_reader(&mut decoder)?);
        }
        Ok(vec)
    }

    /// Convenience function to get a block at a specific height
    async fn get_block_at_height(&self, height: u64) -> Result<Block, Error> {
        let hash = self.get_block_hash(height).await?;
        self.get_block(hash).await
    }

    /// Get a block hash at a specific height
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockhash-by-height>
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        let path = format!("rest/blockhashbyheight/{height}.bin");
        let resp = self.get_bin(&path).await?;
        Ok(deserialize(&resp)?)
    }

    /// Get a block by its hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blocks>
    async fn get_block(&self, hash: BlockHash) -> Result<Block, Error> {
        let path = format!("rest/block/{hash}.bin");
        let resp = self.get_bin(&path).await?;
        Ok(deserialize(&resp)?)
    }

    /// Get a transaction by its `txid`
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#transactions>
    async fn get_transaction(&self, txid: Txid) -> Result<Transaction, Error> {
        let path = format!("rest/tx/{txid}.bin");
        let resp = self.get_bin(&path).await?;
        Ok(deserialize(&resp)?)
    }

    /// Get a series of block filter headers beginning from a block hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockfilter-headers>
    async fn get_block_filter_headers(
        &self,
        start_hash: BlockHash,
        count: u32,
    ) -> Result<Vec<FilterHeader>, Error> {
        let path = format!("rest/blockfilterheaders/basic/{count}/{start_hash}.bin");
        let resp = self.get_bin(&path).await?;

        const BLOCK_FILTER_HEADER_SIZE: usize = 32usize;

        let num = resp.len() / BLOCK_FILTER_HEADER_SIZE;
        let mut vec = Vec::<FilterHeader>::with_capacity(num);
        let mut decoder = Cursor::new(resp);
        for _ in 0..num {
            vec.push(FilterHeader::consensus_decode_from_finite_reader(
                &mut decoder,
            )?);
        }
        Ok(vec)
    }

    /// Get a block filter for a given block hash
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockfilters>
    async fn get_block_filter(&self, hash: BlockHash) -> Result<BlockFilter, Error> {
        let path = format!("rest/blockfilter/basic/{hash}.bin");
        let resp = self.get_bin(&path).await?;
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
    async fn get_chain_info(&self) -> Result<GetBlockchainInfoResult, Error> {
        let path = "rest/chaininfo.json";
        self.get_json(path).await
    }

    /// Get utxos for a given set of outpoints
    ///
    /// Optionally check unconfirmed utxos in the mempool
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#query-utxo-set>
    async fn get_utxos(
        &self,
        outpoints: &[OutPoint],
        check_mempool: bool,
    ) -> Result<GetUtxosResult, Error> {
        let mut path = Vec::with_capacity(1 + if check_mempool { 1 } else { 0 } + outpoints.len());
        path.push("rest/getutxos".to_string());
        if check_mempool {
            path.push("checkmempool".to_string());
        }
        for outpoint in outpoints {
            path.push([outpoint.txid.to_string(), outpoint.vout.to_string()].join("-"));
        }
        let mut path = path.join("/");
        path.push_str(".bin");
        let resp = self.get_bin(&path).await?;

        let mut cursor = Cursor::new(&resp);
        decode_utxos_result(&mut cursor)
    }

    /// Get info on the mempool state
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#memory-pool>
    async fn get_mempool_info(&self) -> Result<GetMempoolInfoResult, Error> {
        let path = "rest/mempool/info.json";
        self.get_json(path).await
    }

    /// Get info for every transaction in the mempool
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#memory-pool>
    async fn get_mempool(&self) -> Result<HashMap<Txid, GetMempoolEntryResult>, Error> {
        let path = "rest/mempool/contents.json";
        self.get_json(path).await
    }

    /// Get the txid for every transaction in the mempool
    /// Only available on Bitcoin Core v25.0.0 and later
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#memory-pool>
    async fn get_mempool_txids(&self) -> Result<Vec<Txid>, Error> {
        let path = "rest/mempool/contents.json?verbose=false";
        self.get_json(path).await
    }

    /// Get the txid for every transaction in the mempool and the mempool sequence
    /// Only available on Bitcoin Core v25.0.0 and later
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#memory-pool>
    async fn get_mempool_txids_and_sequence(
        &self,
    ) -> Result<GetMempoolTxidsAndSequenceResult, Error> {
        let path = "rest/mempool/contents.json?mempool_sequence=true&verbose=false";
        self.get_json(path).await
    }

    /// Get soft fork deployment status info
    /// Only available on Bitcoin Core v25.0.0 and later
    ///
    /// See <https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#deployment-info>
    async fn get_deployment_info(&self) -> Result<GetDeploymentInfoResult, Error> {
        let path = "rest/deploymentinfo.json";
        self.get_json(path).await
    }
}

/// Creates HTTP REST requests to bitcoind.
///
/// See [`RestApi`](RestApi) for the available methods.
#[cfg(feature = "use-reqwest")]
#[derive(Clone)]
pub struct RestClient {
    client: Client,
    endpoint: Url,
}

#[cfg(feature = "use-reqwest")]
impl RestClient {
    /// Create a new `RestClient` instance with given endpoint url
    pub fn new(endpoint: impl IntoUrl) -> Result<Self, Error> {
        Ok(RestClient {
            client: Client::new(),
            endpoint: endpoint.into_url()?,
        })
    }

    /// Create a new `RestClient` instance with the default endpoint for that network
    ///
    /// For example, [`Network::Bitcoin`] creates an instance with `"http://localhost:8332"`
    pub fn network_default(network: Network) -> Self {
        let endpoint = match network {
            Network::Testnet => "http://localhost:18332",
            Network::Signet => "http://localhost:38332",
            Network::Regtest => "http://localhost:18443",
            _ => "http://localhost:8332",
        };

        RestClient {
            client: Client::new(),
            endpoint: endpoint.parse().unwrap(),
        }
    }
}

#[cfg(feature = "use-reqwest")]
#[async_trait]
impl RestApi for RestClient {
    async fn get_json<T: for<'a> Deserialize<'a>>(&self, path: &str) -> Result<T, Error> {
        let url = self.endpoint.join(path).unwrap();
        let response = self.client.get(url).send().await?;

        if response.status() != StatusCode::OK {
            return Err(Error::NotOkError(response.status()));
        }

        response.json::<T>().await.map_err(Error::ReqwestError)
    }

    async fn get_bin(&self, path: &str) -> Result<Bytes, Error> {
        let url = self.endpoint.join(path).unwrap();
        let response = self.client.get(url).send().await?;

        if response.status() != StatusCode::OK {
            return Err(Error::NotOkError(response.status()));
        }

        response.bytes().await.map_err(Error::ReqwestError)
    }
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

fn read_bytes(reader: &mut impl Read, num: usize) -> Result<Vec<u8>, Error> {
    let mut ret = Vec::with_capacity(num);
    for _ in 0..num {
        ret.push(reader.read_u8()?);
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {

    use super::{Error, RestApi, RestClient, StatusCode};

    use bitcoin::{Amount, Network, OutPoint};
    use bitcoind::{bitcoincore_rpc::RpcApi, downloaded_exe_path, BitcoinD, Conf};

    const NUM_BLOCKS: u32 = 101;

    #[tokio::test]
    async fn test_rest() {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut conf = Conf::default();
        conf.args = vec![
            "-rest",
            "-blockfilterindex",
            "-regtest",
            "-fallbackfee=0.0001",
        ];
        let bitcoind = BitcoinD::with_conf(downloaded_exe_path().unwrap(), &conf).unwrap();
        let address = bitcoind
            .client
            .get_new_address(None, None)
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
        bitcoind
            .client
            .generate_to_address(NUM_BLOCKS as u64, &address)
            .unwrap();

        let rpc_socket = bitcoind.params.rpc_socket;

        let bitcoin_rest = RestClient::new(format!("http://{}", rpc_socket)).unwrap();

        let hash = bitcoin_rest
            .get_block_hash(NUM_BLOCKS as u64)
            .await
            .unwrap();
        assert_eq!(
            hash,
            bitcoind.client.get_block_hash(NUM_BLOCKS as u64).unwrap()
        );

        let block = bitcoin_rest
            .get_block_at_height(NUM_BLOCKS as u64)
            .await
            .unwrap();
        assert_eq!(block, bitcoind.client.get_block(&hash).unwrap());
        assert_eq!(block, bitcoin_rest.get_block(hash).await.unwrap());

        let first_hash = bitcoin_rest.get_block_hash(0).await.unwrap();
        let headers = bitcoin_rest
            .get_block_headers(first_hash, NUM_BLOCKS)
            .await
            .unwrap();
        assert_eq!(headers.len(), NUM_BLOCKS as usize);
        assert_eq!(headers[1].prev_blockhash, first_hash);

        let filter_headers = bitcoin_rest
            .get_block_filter_headers(first_hash, NUM_BLOCKS)
            .await
            .unwrap();
        assert_eq!(filter_headers.len(), NUM_BLOCKS as usize);

        let _ = bitcoin_rest.get_block_filter(hash).await.unwrap();

        let txid = bitcoind
            .client
            .send_to_address(
                &address,
                Amount::ONE_BTC,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let txid2 = bitcoind
            .client
            .send_to_address(
                &address,
                Amount::from_btc(0.5).unwrap(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let chain_info = bitcoin_rest.get_chain_info().await.unwrap();
        assert_eq!(chain_info.chain, "regtest");
        assert_eq!(chain_info.blocks, NUM_BLOCKS as u64);
        assert_eq!(chain_info.best_block_hash, hash);

        let deployment_info = bitcoin_rest.get_deployment_info().await.unwrap();
        assert_eq!(deployment_info.hash, hash);
        assert_eq!(deployment_info.height, NUM_BLOCKS);

        let mempool_info = bitcoin_rest.get_mempool_info().await.unwrap();
        assert!(mempool_info.loaded);
        assert_eq!(mempool_info.size, 2);

        let mempool = bitcoin_rest.get_mempool().await.unwrap();
        assert_eq!(mempool.len(), 2);
        let entry = mempool.get(&txid);
        assert_ne!(entry, None);

        let txids = bitcoin_rest.get_mempool_txids().await.unwrap();
        assert_eq!(txids, vec![txid, txid2]);

        let txids_and_sequence = bitcoin_rest.get_mempool_txids_and_sequence().await.unwrap();
        assert_eq!(txids_and_sequence.txids, vec![txid, txid2]);
        assert_eq!(txids_and_sequence.mempool_sequence, 3);

        let tx = bitcoin_rest.get_transaction(txid).await.unwrap();
        assert_eq!(tx.txid(), txid);

        let outpoints = [
            OutPoint::new(txid, 0),
            OutPoint::new(txid, 1),
            OutPoint::new(txid2, 0),
            OutPoint::new(txid2, 1),
        ];
        let utxo_result = bitcoin_rest.get_utxos(&outpoints, true).await.unwrap();
        assert_eq!(utxo_result.chain_height, NUM_BLOCKS);
        assert_eq!(utxo_result.chain_tip_hash, hash);
        assert_eq!(utxo_result.utxos.len(), 3);
        let utxo = &utxo_result.utxos[0];
        assert_eq!(utxo.height, i32::MAX);

        bitcoind.client.generate_to_address(1, &address).unwrap();
        let utxo_result = bitcoin_rest.get_utxos(&outpoints, true).await.unwrap();
        let utxo = &utxo_result.utxos[0];
        assert_eq!(utxo.height, (NUM_BLOCKS + 1) as i32);
        let utxo = &utxo_result.utxos[1];
        if Amount::from_sat(utxo.output.value) == Amount::from_btc(0.5).unwrap() {
            assert_eq!(utxo.output.script_pubkey, address.script_pubkey());
        } else {
            let utxo = &utxo_result.utxos[2];
            assert_eq!(utxo.output.script_pubkey, address.script_pubkey());
        }

        let result = bitcoin_rest.get_block_hash((NUM_BLOCKS + 2) as u64).await;
        match result {
            Err(Error::NotOkError(StatusCode::NOT_FOUND)) => (),
            Err(_) => panic!(),
            Ok(_) => panic!(),
        }
    }
}
