use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Keepalive keeps handshakes fresh on idle tunnels, which the health check relies on.
pub const DEFAULT_PERSISTENT_KEEPALIVE: u16 = 25;

#[derive(Debug, Eq, PartialEq)]
pub struct Config {
    pub addresses: Vec<(Ipv4Addr, u8)>,
    pub set_conf: String,
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<Config> {
    let content = fs::read_to_string(path).context("read WireGuard config")?;
    parse(&content)
}

pub fn parse(content: &str) -> Result<Config> {
    let mut addresses = Vec::new();
    let mut set_conf = String::new();
    let mut section = "";
    let mut peer_has_keepalive = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            close_section(&mut set_conf, section, peer_has_keepalive);
            section = line;
            peer_has_keepalive = false;
            set_conf.push_str(line);
            set_conf.push('\n');
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("invalid WireGuard line in section {section}");
        };
        let key = key.trim();
        let value = value.trim();
        if section == "[Interface]" && key == "Address" {
            for raw_address in value.split(',') {
                let raw_address = raw_address.trim();
                let Some((address, prefix)) = raw_address.split_once('/') else {
                    bail!("invalid tunnel address {raw_address:?}");
                };
                let address: IpAddr = address
                    .parse()
                    .with_context(|| format!("invalid tunnel address {raw_address:?}"))?;
                let prefix: u8 = prefix
                    .parse()
                    .with_context(|| format!("invalid tunnel address {raw_address:?}"))?;
                // IPv6 is not forwarded by this router; ignore IPv6 tunnel addresses.
                let IpAddr::V4(address) = address else {
                    continue;
                };
                if prefix > 32 {
                    bail!("invalid IPv4 tunnel address {raw_address:?}");
                }
                addresses.push((address, prefix));
            }
            continue;
        }
        if section == "[Interface]" && matches!(key, "DNS" | "MTU" | "Table" | "SaveConfig") {
            continue;
        }
        if section == "[Peer]" && key == "PersistentKeepalive" {
            peer_has_keepalive = true;
        }
        set_conf.push_str(key);
        set_conf.push_str(" = ");
        set_conf.push_str(value);
        set_conf.push('\n');
    }
    close_section(&mut set_conf, section, peer_has_keepalive);
    if addresses.is_empty() || !set_conf.contains("PrivateKey =") || !set_conf.contains("[Peer]") {
        bail!("WireGuard config requires an IPv4 address, private key, and peer");
    }
    Ok(Config {
        addresses,
        set_conf,
    })
}

fn close_section(set_conf: &mut String, section: &str, has_keepalive: bool) {
    if section == "[Peer]" && !has_keepalive {
        set_conf.push_str(&format!(
            "PersistentKeepalive = {DEFAULT_PERSISTENT_KEEPALIVE}\n"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_quick_only_fields() {
        let config = parse(
            "[Interface]\nPrivateKey = secret\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\nTable = off\nMTU = 1420\nSaveConfig = false\n\n[Peer]\nPublicKey = public\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 15\n",
        )
        .unwrap();
        assert_eq!(config.addresses, vec![(Ipv4Addr::new(10, 2, 0, 2), 32)]);
        for field in ["Address", "DNS", "Table", "MTU", "SaveConfig"] {
            assert!(!config.set_conf.contains(field));
        }
        assert!(config.set_conf.contains("PersistentKeepalive = 15\n"));
        assert_eq!(config.set_conf.matches("PersistentKeepalive").count(), 1);
    }

    #[test]
    fn ignores_ipv6_tunnel_addresses() {
        let config = parse(
            "[Interface]\nPrivateKey = secret\nAddress = 10.2.0.2/32, 2a07:b944::2:2/128\n[Peer]\nPublicKey = public\nAllowedIPs = 0.0.0.0/0, ::/0\n",
        )
        .unwrap();
        assert_eq!(config.addresses, vec![(Ipv4Addr::new(10, 2, 0, 2), 32)]);
    }

    #[test]
    fn requires_an_ipv4_tunnel_address() {
        assert!(
            parse("[Interface]\nPrivateKey = secret\nAddress = 2a07:b944::2:2/128\n[Peer]\nPublicKey = public\n")
                .is_err()
        );
    }

    #[test]
    fn adds_keepalive_when_missing() {
        let config = parse(
            "[Interface]\nPrivateKey = secret\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = public\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        assert!(config.set_conf.ends_with("PersistentKeepalive = 25\n"));
    }

    #[test]
    fn invalid_line_error_does_not_echo_content() {
        let error = parse("[Interface]\nnot-a-key-value-private-material\n").unwrap_err();
        assert!(!error.to_string().contains("private-material"));
    }
}
