# Rust REST client for Bitcoin Core REST API

This is a Rust REST client library for calling the Bitcoin Core REST API. It
makes it easy to talk to the Bitcoin Core REST interface.

The REST interface is useful for quickly iterating over the blockchain, because
it can request blocks and transactions in binary form without having to
serialize/deserialize into JSON. It is unauthenticated so there's no need to
worry about storing credentials.

It also has API for quickly retrieving large amounts of block headers and BIP157
compact block filter headers. There is also support for getting block chain
info, mempool info, the raw mempool, and querying the utxo set.

### Usage

The Bitcoin Core bitcoind instance must be started with `-rest` on the command
line or `rest=1` in the `bitcoin.conf` file.

```rust
use bitcoin::Block;
use bitcoin_rest::{BitcoinRest, Error};

async fn get_block(height: u64) -> Result<Block, Error> {
    let rest = BitcoinRest::network_default(Network::Bitcoin);
    rest.get_block_at_height(height).await
}

```