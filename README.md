# Rust REST client for Bitcoin Core REST API

A Rust REST client library for calling the Bitcoin Core REST API. It
makes it easy to talk to the Bitcoin Core REST interface.

The REST interface is useful for quickly iterating over the blockchain, because
it can request blocks and transactions in binary form without having to
serialize/deserialize into JSON. It is unauthenticated so there's no need to
worry about storing credentials.

It also has API for quickly retrieving large amounts of block headers and BIP157
compact block filter headers. There is also support for getting block chain
info, mempool info, the raw mempool, querying the utxo set, and soft fork
deployment statuses.

See https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md for
more details.

### Installation

Run the following Cargo command in your project directory:

```bash
cargo add bitcoincore-rest
```

Or add the following line to your Cargo.toml:

```toml
bitcoincore-rest = "4.0.1"
```

### Usage

The Bitcoin Core bitcoind instance must be started with `-rest` on the command
line or `rest=1` in the `bitcoin.conf` file.

```rust
use bitcoincore_rest::prelude::*;

async fn get_block(height: u64) -> Result<Block, Error> {
    let rest = RestClient::network_default(Network::Bitcoin);
    rest.get_block_at_height(height).await
}

```

### API

Unfortunately, `async_trait` trait functions are expanded in docsrs, so here are
the unexpanded functions for `RestApi`, which `RestClient` implements:

```rust
async fn get_block_headers(
    &self,
    start_hash: BlockHash,
    count: u32,
) -> Result<Vec<Header>, Error>;

async fn get_block_at_height(&self, height: u64) -> Result<Block, Error>;

async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error>;

async fn get_block(&self, hash: BlockHash) -> Result<Block, Error>;

async fn get_transaction(&self, txid: Txid) -> Result<Transaction, Error>;

async fn get_block_filter_headers(
    &self,
    start_hash: BlockHash,
    count: u32,
) -> Result<Vec<FilterHeader>, Error>;

async fn get_block_filter(&self, hash: BlockHash) -> Result<BlockFilter, Error>;

async fn get_chain_info(&self) -> Result<GetBlockchainInfoResult, Error>;

async fn get_utxos(
    &self,
    outpoints: &[OutPoint],
    check_mempool: bool,
) -> Result<GetUtxosResult, Error>;

async fn get_mempool_info(&self) -> Result<GetMempoolInfoResult, Error>;

async fn get_mempool(&self) -> Result<HashMap<Txid, GetMempoolEntryResult>, Error>;

async fn get_mempool_txids(&self) -> Result<Vec<Txid>, Error>;

async fn get_mempool_txids_and_sequence(
    &self,
) -> Result<GetMempoolTxidsAndSequenceResult, Error>;

async fn get_deployment_info(&self) -> Result<GetDeploymentInfoResult, Error>;

/// Only available on Bitcoin Core v25.1 and later
///
/// WARNING: CALLING THIS CONNECTED TO BITCOIN CORE V25.0 WILL CRASH BITCOIND
///
/// IT IS MARKED UNSAFE TO ENSURE YOU ARE NOT USING BITCOIN CORE V25.0
async unsafe fn get_deployment_info_at_block(
    &self,
    hash: BlockHash,
) -> Result<GetDeploymentInfoResult, Error>;

```

### Features

By default, this library includes a struct `RestClient` which implements
`RestApi` by using the `reqwest` library. To not use `reqwest` as a dependency
and implement your own version of `RestApi`, set `default-features = false` in
your `Cargo.toml`:

```toml
bitcoincore-rest = { version = "4.0.1", default-features = false }
```

You will have to implement the `get_json` and `get_bin` methods on `RestApi`
with your own http functionality. All methods are `GET` requests. For example,
using the [`surf`](https://docs.rs/surf/latest/surf/) http library and
[`thiserror`](https://docs.rs/thiserror/latest/thiserror/):

```rust
use bitcoincore_rest::{
    async_trait::async_trait, bytes::Bytes, serde::Deserialize, Error, RestApi,
};

#[derive(thiserror::Error, Debug)]
pub enum SurfError {
    #[error("surf error")]
    Surf(surf::Error),
}

struct NewClient;

#[async_trait]
impl RestApi for NewClient {
    async fn get_json<T: for<'a> Deserialize<'a>>(&self, path: &str) -> Result<T, Error> {
        surf::get(format!("http://localhost:8332/{path}"))
            .recv_json()
            .await
            .map_err(|e| Error::CustomError(Box::new(SurfError::Surf(e))))
    }

    async fn get_bin(&self, path: &str) -> Result<Bytes, Error> {
        surf::get(format!("http://localhost:8332/{path}"))
            .recv_bytes()
            .await
            .map_err(|e| Error::CustomError(Box::new(SurfError::Surf(e))))
            .map(Bytes::from)
    }
}
```
