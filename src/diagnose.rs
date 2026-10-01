//! On-demand diagnosis of one location: what was measured, step by step, and
//! what it most likely means.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Serialize;

use crate::health::Status;

/// A handshake at most this old counts as working (as in the health checks).
const RECENT_HANDSHAKE: Duration = Duration::from_secs(180);

/// What the gateway measured for a location.
#[derive(Debug, Default)]
pub struct Findings {
    pub interface_up: bool,
    pub handshake_age: Option<Duration>,
    /// Bytes the tunnel sent and received while the test traffic ran.
    pub sent_during_test: Option<u64>,
    pub received_during_test: Option<u64>,
    pub egress: Option<Result<Ipv4Addr, String>>,
    pub test_time: Duration,
    /// `None` when the tunnel names no resolver.
    pub resolver: Option<Result<(), String>>,
    pub endpoint: Option<SocketAddr>,
    /// Whether the server's host answered TCP (accepted or refused) outside
    /// the tunnel; `None` when not tested.
    pub endpoint_answers: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Step {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Diagnosis {
    pub location: String,
    pub status: Status,
    pub conclusion: String,
    pub steps: Vec<Step>,
}

fn bytes(value: u64) -> String {
    match value {
        0..1024 => format!("{value} B"),
        1024..1_048_576 => format!("{:.1} KB", value as f64 / 1024.0),
        _ => format!("{:.1} MB", value as f64 / 1_048_576.0),
    }
}

pub fn diagnose(location: &str, findings: &Findings) -> Diagnosis {
    let recent = findings
        .handshake_age
        .is_some_and(|age| age <= RECENT_HANDSHAKE);
    let traffic_passes = matches!(findings.egress, Some(Ok(_)));
    let nothing_back = findings.received_during_test == Some(0);

    let mut steps = vec![Step {
        name: "Tunnel interface",
        status: if findings.interface_up {
            Status::Ok
        } else {
            Status::Failed
        },
        detail: if findings.interface_up {
            "up".into()
        } else {
            "missing or down".into()
        },
    }];
    steps.push(Step {
        name: "Handshake",
        status: match findings.handshake_age {
            Some(age) if age <= RECENT_HANDSHAKE => Status::Ok,
            Some(age) if age <= Duration::from_secs(300) => Status::Warning,
            _ => Status::Failed,
        },
        detail: match findings.handshake_age {
            Some(age) => format!("last one {} s ago", age.as_secs()),
            None => "none since the tunnel was created".into(),
        },
    });
    steps.push(Step {
        name: "Traffic through the tunnel",
        status: match &findings.egress {
            Some(Ok(_)) => Status::Ok,
            Some(Err(_)) => Status::Failed,
            None => Status::Unknown,
        },
        detail: match &findings.egress {
            Some(Ok(address)) => format!(
                "public IP {address}, answered in {} ms",
                findings.test_time.as_millis()
            ),
            Some(Err(error)) => format!("no answer: {error}"),
            None => "not tested".into(),
        },
    });
    if let (Some(sent), Some(received)) = (findings.sent_during_test, findings.received_during_test)
    {
        steps.push(Step {
            name: "Tunnel traffic during the test",
            status: if received == 0 {
                Status::Failed
            } else {
                Status::Ok
            },
            detail: format!("sent {}, received {}", bytes(sent), bytes(received)),
        });
    }
    if let Some(resolver) = &findings.resolver {
        steps.push(Step {
            name: "The tunnel's DNS",
            status: if resolver.is_ok() {
                Status::Ok
            } else {
                Status::Warning
            },
            detail: match resolver {
                Ok(()) => "answers".into(),
                Err(error) => format!("no answer: {error}"),
            },
        });
    }
    if let Some(answers) = findings.endpoint_answers {
        let endpoint = findings.endpoint.map_or_else(
            || "the server".to_owned(),
            |endpoint| endpoint.ip().to_string(),
        );
        steps.push(Step {
            name: "Server outside the tunnel",
            status: if answers { Status::Ok } else { Status::Warning },
            detail: if answers {
                format!("{endpoint} answers on TCP 443, so the host is up")
            } else {
                format!("{endpoint} did not answer on TCP 443")
            },
        });
    }

    let (status, conclusion) = if !findings.interface_up {
        (
            Status::Failed,
            "The tunnel interface is missing or down. The gateway recreates it within a reconcile pass (30 seconds).".to_owned(),
        )
    } else if recent && traffic_passes {
        match &findings.resolver {
            Some(Err(_)) => (
                Status::Warning,
                "Traffic passes, but the tunnel's DNS resolver does not answer. Devices on this location with the kill switch on get no DNS.".to_owned(),
            ),
            _ => (
                Status::Ok,
                "Everything works: handshakes are recent and traffic passes.".to_owned(),
            ),
        }
    } else if recent {
        (
            Status::Failed,
            "Handshakes work but traffic does not pass. The provider still accepts the key but does not forward traffic for it: the key, its certificate, or the account may no longer be valid.".to_owned(),
        )
    } else if nothing_back && findings.endpoint_answers == Some(true) {
        (
            Status::Failed,
            "The server's host is up, but nothing comes back through WireGuard. Most likely it does not accept this key (a revoked key or certificate, or an account connection limit), or its VPN service is down. Try another server from the same provider; if all fail, check the account.".to_owned(),
        )
    } else if nothing_back {
        (
            Status::Failed,
            "Nothing comes back from the server, and its address did not answer on TCP 443 either: the server, or the path to it, is probably down. Some servers ignore TCP 443, so this is not certain. Try another server.".to_owned(),
        )
    } else {
        (
            Status::Failed,
            "The server replies, but no handshake completes. The configuration may be outdated or its keys may not match; import it again, or pick another server.".to_owned(),
        )
    };
    Diagnosis {
        location: location.to_owned(),
        status,
        conclusion,
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn working() -> Findings {
        Findings {
            interface_up: true,
            handshake_age: Some(Duration::from_secs(20)),
            sent_during_test: Some(600),
            received_during_test: Some(900),
            egress: Some(Ok(Ipv4Addr::new(146, 70, 86, 117))),
            test_time: Duration::from_millis(120),
            resolver: Some(Ok(())),
            endpoint: Some("146.70.86.114:51820".parse().unwrap()),
            endpoint_answers: Some(true),
        }
    }

    #[test]
    fn concludes_from_what_was_measured() {
        let ok = diagnose("NL#227", &working());
        assert_eq!(ok.status, Status::Ok);
        assert!(ok.steps.iter().all(|step| step.status == Status::Ok));

        // Today's Spain outage: host up, WireGuard silent.
        let silent = diagnose(
            "ES#146",
            &Findings {
                handshake_age: None,
                received_during_test: Some(0),
                egress: Some(Err("timed out".into())),
                ..working()
            },
        );
        assert_eq!(silent.status, Status::Failed);
        assert!(
            silent.conclusion.contains("does not accept this key"),
            "{}",
            silent.conclusion
        );

        let unreachable = diagnose(
            "ES#146",
            &Findings {
                endpoint_answers: Some(false),
                handshake_age: None,
                received_during_test: Some(0),
                egress: Some(Err("timed out".into())),
                ..working()
            },
        );
        assert!(unreachable.conclusion.contains("probably down"));

        let not_forwarding = diagnose(
            "NL#227",
            &Findings {
                egress: Some(Err("timed out".into())),
                ..working()
            },
        );
        assert!(
            not_forwarding
                .conclusion
                .contains("does not forward traffic")
        );

        let no_dns = diagnose(
            "NL#227",
            &Findings {
                resolver: Some(Err("timed out".into())),
                ..working()
            },
        );
        assert_eq!(no_dns.status, Status::Warning);
        assert_eq!(
            diagnose("X", &Findings::default()).status,
            Status::Failed,
            "a missing interface"
        );
    }
}
