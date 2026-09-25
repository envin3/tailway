//! Data-plane probes. A fresh WireGuard handshake only proves the control plane:
//! a provider can complete handshakes for a key it no longer forwards traffic
//! for (Proton does, once the key's certificate expires or its session is
//! jailed). These probes send real
//! packets through a tunnel, selected by its firewall mark, and expect answers.

use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result, bail};

use crate::dns::{self, Upstream};

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
const CLASS_CHAOS: u16 = 3;

/// Public "what is my address" DNS services, tried in order. Two independent
/// operators, so one being down does not fail a working tunnel.
const ECHO_SERVICES: [EchoService; 2] = [
    EchoService {
        server: Ipv4Addr::new(208, 67, 222, 222),
        name: "myip.opendns.com",
        qtype: TYPE_A,
        qclass: CLASS_IN,
    },
    EchoService {
        server: Ipv4Addr::new(1, 1, 1, 1),
        name: "whoami.cloudflare",
        qtype: TYPE_TXT,
        qclass: CLASS_CHAOS,
    },
];

/// Any name works; the answer only has to arrive.
const RESOLVER_PROBE_NAME: &str = "example.com";

struct EchoService {
    server: Ipv4Addr,
    name: &'static str,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    /// The exit's public address as seen on the internet, or why it is unknown.
    pub egress: Result<Ipv4Addr, String>,
    /// Whether the tunnel's own resolver answers (always `Ok` without one).
    pub resolver: Result<(), String>,
}

/// Probe internet egress, and the in-tunnel resolver when the tunnel names
/// one, through the tunnel with `mark`.
pub async fn run(mark: u32, resolver: Option<Ipv4Addr>) -> Outcome {
    let (egress, resolver) = tokio::join!(public_address(mark), tunnel_resolver(mark, resolver));
    Outcome {
        egress: egress.map_err(|error| format!("{error:#}")),
        resolver: resolver.map_err(|error| format!("{error:#}")),
    }
}

async fn public_address(mark: u32) -> Result<Ipv4Addr> {
    let mut errors = Vec::new();
    for service in &ECHO_SERVICES {
        match echo(mark, service).await {
            Ok(address) => return Ok(address),
            Err(error) => errors.push(format!("{}: {error:#}", service.server)),
        }
    }
    bail!("no traffic passes the tunnel ({})", errors.join("; "))
}

async fn echo(mark: u32, service: &EchoService) -> Result<Ipv4Addr> {
    let query = build_query(rand::random(), service.name, service.qtype, service.qclass);
    let response = dns::query_udp(upstream(service.server, mark), &query).await?;
    parse_address(&response, service.qtype)
}

async fn tunnel_resolver(mark: u32, resolver: Option<Ipv4Addr>) -> Result<()> {
    let Some(resolver) = resolver else {
        return Ok(());
    };
    let query = build_query(rand::random(), RESOLVER_PROBE_NAME, TYPE_A, CLASS_IN);
    let response = dns::query_udp(upstream(resolver, mark), &query)
        .await
        .context("the VPN's DNS resolver did not answer")?;
    match rcode(&response)? {
        0 | 3 => Ok(()),
        code => bail!("the VPN's DNS resolver answered with rcode {code}"),
    }
}

fn upstream(server: Ipv4Addr, mark: u32) -> Upstream {
    Upstream {
        address: SocketAddrV4::new(server, 53),
        mark: Some(mark),
    }
}

fn build_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(12 + name.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    // Recursion desired, one question.
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&qclass.to_be_bytes());
    query
}

fn rcode(response: &[u8]) -> Result<u8> {
    if response.len() < 12 {
        bail!("truncated DNS response");
    }
    Ok(response[3] & 0x0f)
}

/// The first answer of type `qtype` holding an IPv4 address: an A record, or a
/// TXT record whose text is an address.
fn parse_address(response: &[u8], qtype: u16) -> Result<Ipv4Addr> {
    let code = rcode(response)?;
    if code != 0 {
        bail!("DNS rcode {code}");
    }
    let field = |offset: usize| -> Result<u16> {
        let bytes = response
            .get(offset..offset + 2)
            .context("truncated DNS response")?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    };
    let questions = field(4)?;
    let answers = field(6)?;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(response, offset)? + 4;
    }
    for _ in 0..answers {
        offset = skip_name(response, offset)?;
        let record_type = field(offset)?;
        let length = usize::from(field(offset + 8)?);
        let start = offset + 10;
        let data = response
            .get(start..start + length)
            .context("truncated DNS response")?;
        offset = start + length;
        if record_type != qtype {
            continue;
        }
        match record_type {
            TYPE_A if length == 4 => {
                return Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            TYPE_TXT => {
                let text_length = usize::from(*data.first().context("empty TXT record")?);
                let text = data
                    .get(1..1 + text_length)
                    .context("truncated TXT record")?;
                return std::str::from_utf8(text)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .context("TXT record is not an IPv4 address");
            }
            _ => {}
        }
    }
    bail!("no address in the DNS response")
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        let length = *message.get(offset).context("truncated DNS name")?;
        match length {
            0 => return Ok(offset + 1),
            // A compression pointer ends the name.
            length if length & 0xc0 == 0xc0 => return Ok(offset + 2),
            length => offset += 1 + usize::from(length),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(query: &[u8], answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut message = query.to_vec();
        message[2] |= 0x80;
        message[7] = answers.len() as u8;
        for (record_type, data) in answers {
            // Pointer to the question name, class IN, TTL 0.
            message.extend_from_slice(&[0xc0, 12]);
            message.extend_from_slice(&record_type.to_be_bytes());
            message.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
            message.extend_from_slice(&(data.len() as u16).to_be_bytes());
            message.extend_from_slice(data);
        }
        message
    }

    #[test]
    fn builds_a_standard_query() {
        let query = build_query(0x1234, "myip.opendns.com", TYPE_A, CLASS_IN);
        assert_eq!(&query[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&query[12..17], b"\x04myip");
        assert!(query.ends_with(&[0, 0, 1, 0, 1]));
    }

    #[test]
    fn reads_an_a_record_after_other_records() {
        let query = build_query(1, "myip.opendns.com", TYPE_A, CLASS_IN);
        let message = response(&query, &[(5, b"\x01x\x00"), (TYPE_A, &[146, 70, 86, 115])]);
        assert_eq!(
            parse_address(&message, TYPE_A).unwrap(),
            Ipv4Addr::new(146, 70, 86, 115)
        );
    }

    #[test]
    fn reads_a_txt_record_address() {
        let query = build_query(1, "whoami.cloudflare", TYPE_TXT, CLASS_CHAOS);
        let message = response(&query, &[(TYPE_TXT, b"\x0d146.70.86.115")]);
        assert_eq!(
            parse_address(&message, TYPE_TXT).unwrap(),
            Ipv4Addr::new(146, 70, 86, 115)
        );
    }

    #[test]
    fn rejects_errors_and_empty_or_malformed_answers() {
        let query = build_query(1, "myip.opendns.com", TYPE_A, CLASS_IN);
        let mut refused = response(&query, &[]);
        refused[3] |= 5;
        assert!(parse_address(&refused, TYPE_A).is_err());
        assert!(parse_address(&response(&query, &[]), TYPE_A).is_err());
        assert!(parse_address(&response(&query, &[(TYPE_TXT, b"\x03abc")]), TYPE_TXT).is_err());
        let mut truncated = response(&query, &[(TYPE_A, &[1, 2, 3, 4])]);
        truncated.truncate(truncated.len() - 2);
        assert!(parse_address(&truncated, TYPE_A).is_err());
        assert!(parse_address(&[0; 4], TYPE_A).is_err());
    }
}
