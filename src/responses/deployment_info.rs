use std::collections::HashMap;

use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

/// Response from `get_deployment_info`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetDeploymentInfoResult {
    pub hash: BlockHash,
    pub height: u32,
    pub deployments: HashMap<String, DeploymentInfo>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type", content = "bip9")]
pub enum DeploymentType {
    Buried,
    Bip9(Bip9),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DeploymentInfo {
    #[serde(flatten)]
    pub r#type: DeploymentType,
    pub height: Option<u32>,
    pub active: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Signalling {
    #[serde(rename = "#")]
    Signalling,
    #[serde(rename = "-")]
    NotSignalling,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bip9 {
    pub bit: Option<u8>,
    pub start_time: i64,
    pub timeout: i64,
    pub min_activation_height: i32,
    pub status: Status,
    pub since: i32,
    pub status_next: Status,
    pub statistics: Option<Statistics>,
    pub signalling: Option<Signalling>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Statistics {
    pub period: u32,
    pub threshold: Option<u32>,
    pub elapsed: u32,
    pub count: u32,
    pub possible: Option<bool>,
}
