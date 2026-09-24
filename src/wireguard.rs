use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};

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
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            set_conf.push_str(line);
            set_conf.push('\n');
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("invalid WireGuard line {line:?}");
        };
        let key = key.trim();
        let value = value.trim();
        if section == "[Interface]" && key == "Address" {
            for raw_address in value.split(',') {
                let raw_address = raw_address.trim();
                let Some((address, prefix)) = raw_address.split_once('/') else {
                    bail!("invalid IPv4 tunnel address {raw_address:?}");
                };
                let address: Ipv4Addr = address
                    .parse()
                    .with_context(|| format!("invalid IPv4 tunnel address {raw_address:?}"))?;
                let prefix: u8 = prefix
                    .parse()
                    .with_context(|| format!("invalid IPv4 tunnel address {raw_address:?}"))?;
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
        set_conf.push_str(key);
        set_conf.push_str(" = ");
        set_conf.push_str(value);
        set_conf.push('\n');
    }
    if addresses.is_empty() || !set_conf.contains("PrivateKey =") || !set_conf.contains("[Peer]") {
        bail!("WireGuard config requires an IPv4 address, private key, and peer");
    }
    Ok(Config {
        addresses,
        set_conf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_quick_only_fields() {
        let config = parse(
            "[Interface]\nPrivateKey = secret\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\nTable = off\nMTU = 1420\nSaveConfig = false\n\n[Peer]\nPublicKey = public\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        assert_eq!(config.addresses, vec![(Ipv4Addr::new(10, 2, 0, 2), 32)]);
        for field in ["Address", "DNS", "Table", "MTU", "SaveConfig"] {
            assert!(!config.set_conf.contains(field));
        }
    }
}
