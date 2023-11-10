//! Response types for REST endpoints that aren't in
//! [`bitcoincore_rpc_json`].

use bitcoin::Txid;
use serde::{Deserialize, Serialize};

pub mod deployment_info;
pub mod get_utxos;

pub use deployment_info::GetDeploymentInfoResult;
pub use get_utxos::GetUtxosResult;

/// Response from `get_mempool_txids_and_sequence`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolTxidsAndSequenceResult {
    pub txids: Vec<Txid>,
    pub mempool_sequence: u64,
}
