use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use serde::Deserialize;

use crate::domain::Device;
use crate::platform::Runner;

#[derive(Clone)]
pub struct Provider {
    runner: Runner,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Status {
    backend_state: String,
    peer: Option<HashMap<String, Peer>>,
    /// Tailscale's own warnings, e.g. no connection to the coordination server.
    health: Option<Vec<String>>,
    #[serde(rename = "Self")]
    self_node: Option<SelfNode>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct SelfNode {
    online: bool,
    key_expiry: Option<String>,
}

/// Tailnet peers plus whether the local Tailscale is connected with a device list.
pub struct Snapshot {
    pub devices: Vec<Device>,
    /// `BackendState == "Running"`: logged in with a network map, so the peer list is
    /// authoritative. Before that (starting, logged out) it may be empty or partial.
    pub running: bool,
    pub connection: Connection,
}

/// How the gateway's own Tailscale node stands with the tailnet.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Connection {
    /// Tailscale's health warnings; empty when all is well.
    pub warnings: Vec<String>,
    /// Whether the coordination server sees the gateway as online. When it
    /// does not, devices may show the exit node as unavailable.
    pub online: bool,
    /// When the gateway's node key expires (Unix seconds); `None` when key
    /// expiry is disabled for it.
    pub key_expiry: Option<u64>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Peer {
    #[serde(rename = "ID")]
    id: String,
    host_name: String,
    #[serde(rename = "DNSName")]
    dns_name: String,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Vec<String>,
    online: bool,
    active: bool,
    #[serde(rename = "OS")]
    os: String,
    last_seen: String,
}

impl Provider {
    pub fn new(runner: Runner) -> Self {
        Self { runner }
    }

    pub async fn devices(&self) -> Result<Vec<Device>> {
        Ok(self.snapshot().await?.devices)
    }

    pub async fn snapshot(&self) -> Result<Snapshot> {
        let output = self.runner.run("tailscale", ["status", "--json"]).await?;
        parse(&output)
    }
}

fn parse(output: &[u8]) -> Result<Snapshot> {
    let current: Status = serde_json::from_slice(output)
        .map_err(|error| anyhow!("decode Tailscale status: {error}"))?;
    let running = current.backend_state == "Running";
    let peers = current.peer.unwrap_or_default();
    let mut devices = Vec::with_capacity(peers.len());
    for peer in peers.into_values() {
        if peer.id.is_empty() {
            continue;
        }
        let display_name = display_name(&peer);
        let addresses = peer
            .tailscale_ips
            .into_iter()
            .filter_map(|address| address.parse::<IpAddr>().ok())
            .filter(IpAddr::is_ipv4)
            .collect();
        devices.push(Device {
            node_id: peer.id,
            display_name,
            addresses,
            online: peer.online,
            active: peer.active,
            os: peer.os,
            // Tailscale reports the zero time for devices it has not seen offline.
            last_seen: Some(peer.last_seen)
                .filter(|seen| !seen.is_empty() && !seen.starts_with("0001-")),
        });
    }
    devices.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let self_node = current.self_node.unwrap_or_default();
    let connection = Connection {
        warnings: current.health.unwrap_or_default(),
        online: self_node.online,
        key_expiry: self_node
            .key_expiry
            .as_deref()
            .and_then(|expiry| humantime::parse_rfc3339_weak(expiry).ok())
            .and_then(|expiry| expiry.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|expiry| expiry.as_secs()),
    };
    Ok(Snapshot {
        devices,
        running,
        connection,
    })
}

fn display_name(peer: &Peer) -> String {
    peer.dns_name
        .split('.')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            if peer.host_name.is_empty() {
                &peer.id
            } else {
                &peer.host_name
            }
        })
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tailscale_acronym_fields() {
        let status: Status = serde_json::from_str(
            r#"{"Peer":{"key":{"ID":"node-a","HostName":"laptop","DNSName":"laptop.example.ts.net.","TailscaleIPs":["100.64.0.10","fd7a:115c:a1e0::1"],"Online":true,"Active":true}}}"#,
        )
        .unwrap();
        let peer = status.peer.as_ref().unwrap().get("key").unwrap();
        assert_eq!(peer.id, "node-a");
        assert_eq!(peer.tailscale_ips, ["100.64.0.10", "fd7a:115c:a1e0::1"]);
        assert_eq!(display_name(peer), "laptop");
        assert!(peer.active);
    }

    #[test]
    fn reports_os_and_a_real_last_seen_time_only() {
        let snapshot = parse(
            br#"{"BackendState":"Running","Peer":{
                "a":{"ID":"a","HostName":"phone","OS":"iOS","LastSeen":"2026-09-24T14:09:15.1Z","TailscaleIPs":["100.64.0.1"]},
                "b":{"ID":"b","HostName":"server","OS":"linux","LastSeen":"0001-01-01T00:00:00Z","TailscaleIPs":["100.64.0.2"]}}}"#,
        )
        .unwrap();
        let phone = &snapshot.devices[0];
        assert_eq!(
            (phone.os.as_str(), phone.last_seen.as_deref()),
            ("iOS", Some("2026-09-24T14:09:15.1Z"))
        );
        assert_eq!(snapshot.devices[1].last_seen, None);
    }

    #[test]
    fn prefers_tailnet_name_over_local_hostname() {
        let peer: Peer = serde_json::from_str(
            r#"{"ID":"node-a","HostName":"5ecc4cb1dbe8","DNSName":"jellyfin.example.ts.net."}"#,
        )
        .unwrap();
        assert_eq!(display_name(&peer), "jellyfin");
    }

    #[test]
    fn accepts_sparse_peer_status() {
        let status: Status = serde_json::from_str(r#"{"Peer":{"key":{"ID":"node-a"}}}"#).unwrap();
        let peer = status.peer.as_ref().unwrap().get("key").unwrap();
        assert_eq!(peer.id, "node-a");
        assert!(peer.host_name.is_empty());
        assert!(peer.tailscale_ips.is_empty());
        assert!(!peer.online);
        assert!(!peer.active);
        assert_eq!(display_name(peer), "node-a");
    }

    #[test]
    fn reports_whether_tailscale_is_running() {
        let running = parse(br#"{"BackendState":"Running","Peer":{"k":{"ID":"node-a"}}}"#).unwrap();
        assert!(running.running);
        assert_eq!(running.devices.len(), 1);
        for state in ["Starting", "NeedsLogin", "Stopped", ""] {
            let snapshot =
                parse(format!(r#"{{"BackendState":"{state}","Peer":null}}"#).as_bytes()).unwrap();
            assert!(!snapshot.running, "{state} treated as running");
        }
    }

    #[test]
    fn reads_the_gateways_own_connection() {
        let snapshot = parse(
            br#"{"BackendState":"Running","Health":["Unable to connect to the Tailscale coordination server to synchronize the state of your tailnet."],"Self":{"Online":false,"KeyExpiry":"2027-03-05T10:00:00Z"}}"#,
        )
        .unwrap();
        assert!(!snapshot.connection.online);
        assert_eq!(snapshot.connection.warnings.len(), 1);
        assert_eq!(snapshot.connection.key_expiry, Some(1_804_240_800));
        let healthy =
            parse(br#"{"BackendState":"Running","Health":null,"Self":{"Online":true}}"#).unwrap();
        assert_eq!(
            healthy.connection,
            Connection {
                warnings: Vec::new(),
                online: true,
                key_expiry: None,
            }
        );
    }

    #[test]
    fn accepts_null_peer_set_during_startup() {
        let status: Status = serde_json::from_str(r#"{"Peer":null}"#).unwrap();
        assert!(status.peer.is_none());
    }
}
