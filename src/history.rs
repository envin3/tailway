//! Turns what the reconciler observes into events for the history: locations
//! connecting and failing, and devices whose effective route changed.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use crate::domain::{Assignment, Device, Exit, ExitStatus};
use crate::events::{Category, Event, Severity};
use crate::policy::routable;

/// The last recorded state of a location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recorded {
    pub status: ExitStatus,
    pub public_ip: String,
}

/// The event for a location's new state, if it is worth one, and whether to
/// remember the new state. A failed tunnel is rebuilt every minute or so and
/// passes through "connecting" each time; that is not news until it connects.
pub fn location_event(previous: Option<&Recorded>, exit: &Exit) -> (Option<Event>, bool) {
    let name = &exit.display_name;
    let health = |severity, kind: &str, message: String| {
        Some(Event::new(severity, Category::Health, kind, message).subject(name.clone()))
    };
    let connected = |recovered: bool| {
        let verb = if recovered { "recovered" } else { "connected" };
        let message = if exit.public_ip.is_empty() {
            format!("{name} {verb}")
        } else {
            format!("{name} {verb}; public IP {}", exit.public_ip)
        };
        health(Severity::Info, "location.connected", message)
    };
    let previous_status = previous.map(|recorded| recorded.status);
    let event = match (previous_status, exit.status) {
        (_, ExitStatus::Pending)
            if previous_status != Some(ExitStatus::Healthy)
                && previous_status != Some(ExitStatus::Degraded) =>
        {
            return (None, false);
        }
        (Some(before), after) if before == after => {
            let previous = previous
                .map(|recorded| recorded.public_ip.as_str())
                .unwrap_or("");
            if after == ExitStatus::Healthy
                && !previous.is_empty()
                && !exit.public_ip.is_empty()
                && previous != exit.public_ip
            {
                health(
                    Severity::Info,
                    "location.ip_changed",
                    format!("{name} public IP changed to {}", exit.public_ip),
                )
            } else {
                None
            }
        }
        (_, ExitStatus::Pending) => health(
            Severity::Info,
            "location.reconnecting",
            format!("{name} is reconnecting"),
        ),
        (before, ExitStatus::Healthy) => connected(matches!(
            before,
            Some(ExitStatus::Failed | ExitStatus::Degraded)
        )),
        (_, ExitStatus::Degraded) => health(
            Severity::Warning,
            "location.degraded",
            format!("{name} is degraded: {}", exit.status_detail),
        ),
        (_, ExitStatus::Failed) => health(
            Severity::Error,
            "location.down",
            format!(
                "{name} is down; its devices are blocked: {}",
                exit.status_detail
            ),
        ),
    };
    (event, true)
}

/// One event per device whose effective route changed between two applied
/// rule sets (keyed by tailnet address).
pub fn route_events(
    previous: &BTreeMap<Ipv4Addr, String>,
    current: &BTreeMap<Ipv4Addr, String>,
    devices: &[Device],
    exits: &[Exit],
    previous_exits: &[Exit],
    assignments: &[Assignment],
) -> Vec<Event> {
    let owner: HashMap<Ipv4Addr, &Device> = devices
        .iter()
        .flat_map(|device| {
            device
                .addresses
                .iter()
                .filter_map(move |address| match address {
                    IpAddr::V4(address) => Some((*address, device)),
                    IpAddr::V6(_) => None,
                })
        })
        .collect();
    // Current locations win; removed ones are still known by name.
    let exits: HashMap<&str, &Exit> = previous_exits
        .iter()
        .chain(exits)
        .map(|exit| (exit.id.as_str(), exit))
        .collect();
    let assigned: HashMap<&str, &str> = assignments
        .iter()
        .map(|assignment| (assignment.node_id.as_str(), assignment.exit_id.as_str()))
        .collect();
    let label = |route: Option<&String>| match route.map(String::as_str) {
        None => "none".to_owned(),
        Some("block") => "blocked".into(),
        Some("direct") => "direct Internet".into(),
        Some("local") => "local network only".into(),
        Some(route) => route
            .strip_prefix("exit:")
            .and_then(|id| exits.get(id))
            .map_or_else(|| route.to_owned(), |exit| exit.display_name.clone()),
    };
    let mut events = Vec::new();
    let addresses = previous
        .keys()
        .chain(current.keys())
        .collect::<std::collections::BTreeSet<_>>();
    for address in addresses {
        let (before, after) = (previous.get(address), current.get(address));
        if before == after {
            continue;
        }
        // A device's first address appearing or its last leaving is the
        // tailnet changing, not a route.
        let (Some(_), Some(after_route)) = (before, after) else {
            continue;
        };
        let device = owner.get(address);
        let name = device.map_or_else(|| address.to_string(), |device| device.display_name.clone());
        let mut message = format!("{name}: {} → {}", label(before), label(after));
        let blocked = after_route == "block";
        if blocked
            && let Some(exit) = device
                .and_then(|device| assigned.get(device.node_id.as_str()))
                .and_then(|exit_id| exits.get(exit_id))
            && !routable(&exit.status)
        {
            message.push_str(&format!(" while {} is down", exit.display_name));
        }
        let severity = if blocked {
            Severity::Warning
        } else {
            Severity::Info
        };
        events.push(Event::new(severity, Category::Health, "route.changed", message).subject(name));
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(status: ExitStatus, public_ip: &str) -> Exit {
        Exit {
            id: "exit-es".into(),
            display_name: "ES#146".into(),
            status,
            status_detail: "no handshake since the tunnel was created".into(),
            public_ip: public_ip.into(),
            ..Exit::default()
        }
    }

    fn recorded(status: ExitStatus, public_ip: &str) -> Recorded {
        Recorded {
            status,
            public_ip: public_ip.into(),
        }
    }

    fn message(result: (Option<Event>, bool)) -> Option<String> {
        result.0.map(|event| event.message)
    }

    #[test]
    fn records_connecting_failing_and_recovering_without_the_rebuild_noise() {
        // First sight while still connecting: wait for the outcome.
        assert_eq!(
            location_event(None, &exit(ExitStatus::Pending, "")),
            (None, false)
        );
        assert_eq!(
            message(location_event(
                None,
                &exit(ExitStatus::Healthy, "79.127.139.149")
            ))
            .unwrap(),
            "ES#146 connected; public IP 79.127.139.149"
        );
        let down = location_event(
            Some(&recorded(ExitStatus::Healthy, "79.127.139.149")),
            &exit(ExitStatus::Failed, ""),
        );
        assert_eq!(down.0.as_ref().unwrap().severity, Severity::Error);
        assert!(down.0.unwrap().message.starts_with("ES#146 is down"));
        // Rebuilding after a failure passes through Pending: nothing new.
        let failed = recorded(ExitStatus::Failed, "");
        assert_eq!(
            location_event(Some(&failed), &exit(ExitStatus::Pending, "")),
            (None, false)
        );
        assert_eq!(
            message(location_event(Some(&failed), &exit(ExitStatus::Failed, ""))),
            None
        );
        assert_eq!(
            message(location_event(
                Some(&failed),
                &exit(ExitStatus::Healthy, "1.2.3.4")
            ))
            .unwrap(),
            "ES#146 recovered; public IP 1.2.3.4"
        );
        assert_eq!(
            message(location_event(
                Some(&recorded(ExitStatus::Healthy, "1.2.3.4")),
                &exit(ExitStatus::Healthy, "5.6.7.8")
            ))
            .unwrap(),
            "ES#146 public IP changed to 5.6.7.8"
        );
        assert_eq!(
            message(location_event(
                Some(&recorded(ExitStatus::Healthy, "1.2.3.4")),
                &exit(ExitStatus::Pending, "")
            ))
            .unwrap(),
            "ES#146 is reconnecting"
        );
    }

    #[test]
    fn explains_route_changes_by_device_name() {
        let address = Ipv4Addr::new(100, 113, 53, 91);
        let device = Device {
            node_id: "node-desktop".into(),
            display_name: "envin-desktop".into(),
            addresses: vec![IpAddr::V4(address)],
            ..Device::default()
        };
        let exits = [exit(ExitStatus::Failed, "")];
        let assignments = [Assignment {
            node_id: "node-desktop".into(),
            exit_id: "exit-es".into(),
        }];
        let previous = BTreeMap::from([(address, "exit:exit-es".to_owned())]);
        let current = BTreeMap::from([(address, "block".to_owned())]);
        let events = route_events(
            &previous,
            &current,
            std::slice::from_ref(&device),
            &exits,
            &[],
            &assignments,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].message,
            "envin-desktop: ES#146 → blocked while ES#146 is down"
        );
        assert_eq!(events[0].severity, Severity::Warning);
        assert_eq!(events[0].subject.as_deref(), Some("envin-desktop"));

        let direct = BTreeMap::from([(address, "direct".to_owned())]);
        let events = route_events(
            &current,
            &direct,
            std::slice::from_ref(&device),
            &exits,
            &[],
            &assignments,
        );
        assert_eq!(
            events[0].message,
            "envin-desktop: blocked → direct Internet"
        );
        assert_eq!(events[0].severity, Severity::Info);
        // Devices joining or leaving the tailnet are not route changes.
        assert!(
            route_events(&BTreeMap::new(), &current, &[], &exits, &[], &assignments).is_empty()
        );

        // Moving off a location that this same change removed: still by name.
        let removed = Exit {
            id: "exit-ad".into(),
            display_name: "AD#1".into(),
            ..Exit::default()
        };
        let before = BTreeMap::from([(address, "exit:exit-ad".to_owned())]);
        let after = BTreeMap::from([(address, "exit:exit-es".to_owned())]);
        let events = route_events(
            &before,
            &after,
            &[device],
            &[exit(ExitStatus::Healthy, "")],
            &[removed],
            &[],
        );
        assert_eq!(events[0].message, "envin-desktop: AD#1 → ES#146");
    }
}
