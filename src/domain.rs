use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const LOCAL_ROUTE_ID: &str = "__local__";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitStatus {
    #[default]
    Pending,
    Healthy,
    Degraded,
    Failed,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exit {
    pub id: String,
    pub display_name: String,
    pub server_id: String,
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(skip)]
    pub interface: String,
    #[serde(skip)]
    pub mark: u32,
    #[serde(skip)]
    pub table: u32,
    pub status: ExitStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_ip: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub node_id: String,
    pub display_name: String,
    pub addresses: Vec<IpAddr>,
    pub online: bool,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub node_id: String,
    pub exit_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub id: String,
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(skip)]
    pub config_file: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredState {
    pub schema_version: u32,
    pub revision: u64,
    pub exits: Vec<Exit>,
    pub assignments: Vec<Assignment>,
}

impl Default for DesiredState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            exits: Vec::new(),
            assignments: Vec::new(),
        }
    }
}
