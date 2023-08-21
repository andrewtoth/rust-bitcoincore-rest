//! Response types for REST endpoints that aren't in
//! [`rust-bitcoincore-rpc`](rust-bitcoincore-rpc).

use bitcoin::Txid;
use serde::{Deserialize, Serialize};

pub mod deployment_info;
pub mod get_utxos;

/// Response from `get_mempool_txids_and_sequence`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolTxidsAndSequenceResult {
    pub txids: Vec<Txid>,
    pub mempool_sequence: u64,
}
