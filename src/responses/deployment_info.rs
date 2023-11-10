//! Response types for `get_deployment_info`.
//!
//! See <https://bitcoincore.org/en/doc/25.0.0/rpc/blockchain/getdeploymentinfo/>

use std::collections::HashMap;

use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

/// Response from `get_deployment_info`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetDeploymentInfoResult {
    /// requested block hash or tip
    pub hash: BlockHash,
    /// requested block height or tip
    pub height: u32,
    /// deployment info keyed by name of the deployment
    pub deployments: HashMap<String, DeploymentInfo>,
}

/// The deployment type indicates if the deployment is buried or is bip9 softfork
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type", content = "bip9")]
pub enum DeploymentType {
    Buried,
    Bip9(Bip9),
}

/// The deployment information
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DeploymentInfo {
    #[serde(flatten)]
    pub r#type: DeploymentType,
    /// height of the first block which the rules are or will be enforced
    ///
    /// `None` if `DeploymentType::Bip9` and `active` is `false`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    pub active: bool,
}

/// The deployment status
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

/// Whether the block is signalling
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Signalling {
    #[serde(rename = "#")]
    Signalling,
    #[serde(rename = "-")]
    NotSignalling,
}

/// Deployment information for bip9 softforks
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bip9 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit: Option<u8>,
    pub start_time: i64,
    pub timeout: i64,
    pub min_activation_height: i32,
    pub status: Status,
    pub since: i32,
    pub status_next: Status,
    /// `None` for `Defined`, `Active`, and `Failed` status
    pub statistics: Option<Statistics>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "signalling_serde"
    )]
    pub signalling: Option<Vec<Signalling>>,
}

/// Numeric statistics about signalling for a softfork
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Statistics {
    pub period: u32,
    /// `Some` only for `Started` status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,
    pub elapsed: u32,
    pub count: u32,
    /// `Some` only for `Started` status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub possible: Option<bool>,
}

mod signalling_serde {
    use super::Signalling;

    pub fn serialize<S: serde::Serializer>(
        val: &Option<Vec<Signalling>>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        if let Some(val) = val {
            use super::Signalling::*;
            let val = val
                .iter()
                .map(|s| match s {
                    Signalling => '#',
                    NotSignalling => '-',
                })
                .collect::<String>();

            ser.serialize_some(val.as_str())
        } else {
            ser.serialize_none()
        }
    }

    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Option<Vec<Signalling>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("sequence of '#' or '-' characters")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(self)
        }

        fn visit_str<E: serde::de::Error>(self, val: &str) -> Result<Self::Value, E> {
            use super::Signalling::*;
            let mut vec = Vec::with_capacity(val.len());
            for b in val.as_bytes() {
                let s = match b {
                    b'#' => Signalling,
                    b'-' => NotSignalling,
                    _ => {
                        return Err(E::invalid_value(
                            serde::de::Unexpected::Bytes(val.as_bytes()),
                            &self,
                        ));
                    }
                };
                vec.push(s);
            }
            Ok(Some(vec))
        }
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Option<Vec<Signalling>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        de.deserialize_option(Visitor)
    }
}

#[cfg(test)]
mod test {

    use super::{DeploymentType, GetDeploymentInfoResult, Signalling};

    #[test]
    fn test_deployment_info_roundtrip() {
        let json = r##"
        {"hash":"2fad8afdcb4c14f11987bc721fd61ab68d0c817a7585267b2eb57f7e11202eb6","height":218,"deployments":{"bip34":{"type":"buried","active":true,"height":1},"bip66":{"type":"buried","active":true,"height":1},"bip65":{"type":"buried","active":true,"height":1},"csv":{"type":"buried","active":true,"height":1},"segwit":{"type":"buried","active":true,"height":0},"testdummy":{"type":"bip9","active":false,"bip9":{"bit":28,"start_time":0,"timeout":9223372036854775807,"min_activation_height":0,"status":"started","since":144,"status_next":"started","statistics":{"period":144,"elapsed":75,"count":75,"threshold":108,"possible":true},"signalling":"#-#-#"}},"taproot":{"type":"bip9","height":0,"active":true,"bip9":{"start_time":-1,"timeout":9223372036854775807,"min_activation_height":0,"status":"active","since":0,"status_next":"active"}}}}
        "##;
        let deployment_info: GetDeploymentInfoResult =
            serde_json::from_str(json).expect("deserialize deployment info");
        let deployment_info =
            serde_json::to_string(&deployment_info).expect("serialize deployment info");
        let deployment_info: GetDeploymentInfoResult =
            serde_json::from_str(&deployment_info).expect("deserialize deployment info again");
        let DeploymentType::Bip9(ref bip9) =
            deployment_info.deployments.get("testdummy").unwrap().r#type
        else {
            panic!("incorrect deployment type for testdummy");
        };
        let signalling = bip9.signalling.as_ref().unwrap();
        assert_eq!(signalling.len(), 5);
        assert_eq!(signalling[0], Signalling::Signalling);
        assert_eq!(signalling[1], Signalling::NotSignalling);
        assert_eq!(signalling[2], Signalling::Signalling);
        assert_eq!(signalling[3], Signalling::NotSignalling);
        assert_eq!(signalling[4], Signalling::Signalling);
    }
}
