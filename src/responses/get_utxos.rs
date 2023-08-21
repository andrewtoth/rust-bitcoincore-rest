//! Response types for `get_utxos`.

use bitcoin::{BlockHash, TxOut};
use serde::{Deserialize, Serialize};

/// Response from `get_utxos`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetUtxosResult {
    pub chain_height: u32,
    pub chain_tip_hash: BlockHash,
    pub bitmap: Vec<u8>,
    pub utxos: Vec<Utxo>,
}

/// Sub object containing height and output from `get_utxos`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Utxo {
    pub height: i32,
    pub output: TxOut,
}
