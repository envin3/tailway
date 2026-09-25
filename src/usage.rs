//! Which tailnet devices use this gateway as their exit node.
//!
//! Tailscale does not tell an exit node who selected it; that preference lives
//! on each client. A client that selected it, though, sends its Internet-bound
//! traffic here. A separate, observe-only nftables table records every tailnet
//! source address that forwards traffic to a public destination through the
//! gateway, including traffic the policy then blocks. Entries expire after
//! `WINDOW`. The table is never flushed with the policy table, so what it
//! learned survives reconciles, and its chain always accepts: it cannot change
//! what is forwarded.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

pub const TABLE: &str = "tailscale_exit_policy_router_usage";
pub const SET: &str = "clients";
/// How long after its last packet a device still counts as using the gateway.
pub const WINDOW: Duration = Duration::from_secs(15 * 60);

/// Destinations that are not the Internet: tailnet, private, loopback,
/// link-local, multicast and reserved. Traffic to these can reach the gateway
/// without the exit node being selected (subnet routes, for example).
const NOT_INTERNET: &str = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3";

/// Idempotent: creates the table on first use and replaces only its rule, so
/// the recorded addresses are kept.
pub fn ruleset(tailscale_interface: &str) -> String {
    let window = WINDOW.as_secs();
    format!(
        "table inet {TABLE} {{\n  set {SET} {{\n    type ipv4_addr\n    flags dynamic, timeout\n    timeout {window}s\n    size 4096\n  }}\n  chain forward {{\n    type filter hook forward priority filter - 10; policy accept;\n  }}\n}}\n\
flush chain inet {TABLE} forward\n\
table inet {TABLE} {{\n  chain forward {{\n    iifname \"{tailscale_interface}\" ip saddr 100.64.0.0/10 ip daddr != {{ {NOT_INTERNET} }} update @{SET} {{ ip saddr }}\n  }}\n}}\n"
    )
}

#[derive(Deserialize)]
struct Listing {
    nftables: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Set {
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    elem: Vec<serde_json::Value>,
}

/// Seconds since each recorded address last sent Internet traffic, from
/// `nft -j list set inet <TABLE> <SET>`.
pub fn parse(json: &[u8]) -> Result<HashMap<Ipv4Addr, u64>> {
    let listing: Listing = serde_json::from_slice(json).context("parse the nftables usage set")?;
    let mut usage = HashMap::new();
    for entry in listing.nftables {
        let Some(set) = entry.get("set") else {
            continue;
        };
        let set: Set =
            serde_json::from_value(set.clone()).context("parse the nftables usage set")?;
        let window = set.timeout.unwrap_or(WINDOW.as_secs());
        for element in set.elem {
            // A plain address, or {"elem": {"val": ..., "expires": ..., "timeout": ...}}.
            let (value, timeout, expires) = match element.get("elem") {
                Some(inner) => (
                    inner.get("val").and_then(serde_json::Value::as_str),
                    inner
                        .get("timeout")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(window),
                    inner
                        .get("expires")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(window),
                ),
                None => (element.as_str(), window, window),
            };
            if let Some(address) = value.and_then(|value| value.parse::<Ipv4Addr>().ok()) {
                usage.insert(address, timeout.saturating_sub(expires));
            }
        }
    }
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_only_tailnet_sources_sending_to_the_internet() {
        let ruleset = ruleset("tailscale0");
        assert!(ruleset.contains("flush chain inet tailscale_exit_policy_router_usage forward"));
        assert!(!ruleset.contains("flush table"));
        assert!(ruleset.contains("policy accept;"));
        assert!(ruleset.contains("timeout 900s"));
        assert!(ruleset.contains(r#"iifname "tailscale0" ip saddr 100.64.0.0/10 ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10"#));
        assert!(ruleset.contains("update @clients { ip saddr }"));
    }

    #[test]
    fn parses_the_time_since_last_traffic() {
        // Captured from nftables 1.0.6.
        let json = br#"{"nftables": [{"metainfo": {"version": "1.0.6", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "clients", "table": "tailscale_exit_policy_router_usage", "type": "ipv4_addr", "handle": 1, "size": 4096, "flags": ["timeout"], "timeout": 900, "elem": [{"elem": {"val": "100.64.0.99", "expires": 896}}, {"elem": {"val": "100.64.0.7", "timeout": 600, "expires": 100}}, "100.64.0.8", {"elem": {"val": "not-an-address", "expires": 1}}]}}]}"#;
        let usage = parse(json).unwrap();
        assert_eq!(usage.len(), 3);
        assert_eq!(usage[&Ipv4Addr::new(100, 64, 0, 99)], 4);
        assert_eq!(usage[&Ipv4Addr::new(100, 64, 0, 7)], 500);
        assert_eq!(usage[&Ipv4Addr::new(100, 64, 0, 8)], 0);
        assert!(parse(br#"{"nftables": []}"#).unwrap().is_empty());
        assert!(parse(b"garbage").is_err());
    }
}
