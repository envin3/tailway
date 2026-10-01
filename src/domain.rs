use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const LOCAL_ROUTE_ID: &str = "__local__";
pub const DIRECT_ROUTE_ID: &str = "__direct__";

pub fn is_builtin_route(exit_id: &str) -> bool {
    exit_id == LOCAL_ROUTE_ID || exit_id == DIRECT_ROUTE_ID
}

/// Route applied to tailnet peers that have no explicit assignment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UnassignedPolicy {
    #[default]
    Block,
    Local,
    Direct,
}

impl UnassignedPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Local => "local",
            Self::Direct => "direct",
        }
    }
}

impl std::str::FromStr for UnassignedPolicy {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "block" => Ok(Self::Block),
            "local" => Ok(Self::Local),
            "direct" => Ok(Self::Direct),
            other => {
                anyhow::bail!("invalid UNASSIGNED_POLICY {other:?}; use block, local, or direct")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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
    pub status_detail: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_ip: String,
    /// In-tunnel resolver from the tunnel's `DNS =` line, known at runtime.
    #[serde(skip)]
    pub resolver: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub node_id: String,
    pub display_name: String,
    pub addresses: Vec<IpAddr>,
    pub online: bool,
    pub active: bool,
    /// Operating system as Tailscale reports it (`iOS`, `macOS`, `linux`, …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    /// When an offline device was last connected (RFC 3339), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub node_id: String,
    pub exit_id: String,
}

/// Per-node DNS overrides; unset fields use the gateway defaults.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDns {
    pub node_id: String,
    /// Whether a Proton-routed node loses DNS when its tunnel is down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_switch: Option<bool>,
    /// DNS server for nodes not on a Proton exit, and the fallback when the
    /// kill switch is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub id: String,
    /// Where the server comes from: the Proton account, or an imported config.
    #[serde(default)]
    pub source: ServerSource,
    /// Provider shown to people ("Proton VPN", "Mullvad", …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider: String,
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerSource {
    /// Managed through the Proton account broker (counts toward its connection limit).
    #[default]
    Proton,
    /// A WireGuard configuration imported by hand, from any provider.
    Custom,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredState {
    pub schema_version: u32,
    pub revision: u64,
    pub exits: Vec<Exit>,
    pub assignments: Vec<Assignment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<NodeDns>,
}

impl Default for DesiredState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            exits: Vec::new(),
            assignments: Vec::new(),
            dns: Vec::new(),
        }
    }
}
