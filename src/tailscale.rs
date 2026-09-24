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
}

/// Tailnet peers plus whether the local Tailscale is connected with a device list.
pub struct Snapshot {
    pub devices: Vec<Device>,
    /// `BackendState == "Running"`: logged in with a network map, so the peer list is
    /// authoritative. Before that (starting, logged out) it may be empty or partial.
    pub running: bool,
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
        });
    }
    devices.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(Snapshot { devices, running })
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
    fn accepts_null_peer_set_during_startup() {
        let status: Status = serde_json::from_str(r#"{"Peer":null}"#).unwrap();
        assert!(status.peer.is_none());
    }
}
