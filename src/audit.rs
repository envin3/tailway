//! Describes a settings change for the event history, by comparing the
//! desired state (and imported locations) before and after a request.

use std::collections::{BTreeMap, HashMap};

use crate::domain::{DIRECT_ROUTE_ID, DesiredState, LOCAL_ROUTE_ID, NodeDns, Server};

/// Headers the console sets when it forwards a request: who asked, from where.
pub const ACTOR_HEADER: &str = "x-tailway-actor";
pub const CLIENT_HEADER: &str = "x-tailway-client";

/// The state a change is judged against.
#[derive(Default)]
pub struct Snapshot {
    pub desired: Option<DesiredState>,
    /// Imported WireGuard locations.
    pub imported: Vec<Server>,
}

/// One line per change, each with the location or device it concerns.
pub fn describe(
    before: &Snapshot,
    after: &Snapshot,
    device_names: &HashMap<String, String>,
) -> Vec<(String, Option<String>)> {
    let mut changes = Vec::new();
    let device = |node_id: &str| {
        device_names
            .get(node_id)
            .cloned()
            .unwrap_or_else(|| node_id.to_owned())
    };

    let imported = |snapshot: &Snapshot| -> BTreeMap<String, String> {
        snapshot
            .imported
            .iter()
            .map(|server| (server.id.clone(), server.name.clone()))
            .collect()
    };
    let (imported_before, imported_after) = (imported(before), imported(after));
    for (id, name) in &imported_after {
        if !imported_before.contains_key(id) {
            changes.push((
                format!("Imported WireGuard location {name}"),
                Some(name.clone()),
            ));
        }
    }
    for (id, name) in &imported_before {
        if !imported_after.contains_key(id) {
            changes.push((
                format!("Removed WireGuard location {name}"),
                Some(name.clone()),
            ));
        }
    }

    let (Some(before), Some(after)) = (&before.desired, &after.desired) else {
        return changes;
    };
    let exits = |state: &DesiredState| -> BTreeMap<String, (String, String)> {
        state
            .exits
            .iter()
            .map(|exit| {
                (
                    exit.id.clone(),
                    (exit.display_name.clone(), exit.server_id.clone()),
                )
            })
            .collect()
    };
    let (exits_before, exits_after) = (exits(before), exits(after));
    for (id, (name, server)) in &exits_after {
        match exits_before.get(id) {
            None => changes.push((format!("Added location {name}"), Some(name.clone()))),
            Some((old_name, old_server)) if old_server != server || old_name != name => changes
                .push((
                    format!("Switched location {old_name} to {name}"),
                    Some(name.clone()),
                )),
            Some(_) => {}
        }
    }
    for (id, (name, _)) in &exits_before {
        if !exits_after.contains_key(id) {
            changes.push((format!("Removed location {name}"), Some(name.clone())));
        }
    }

    let route_label = |exit_id: &str| match exit_id {
        DIRECT_ROUTE_ID => "direct Internet".to_owned(),
        LOCAL_ROUTE_ID => "local network only".to_owned(),
        exit_id => exits_after
            .get(exit_id)
            .or_else(|| exits_before.get(exit_id))
            .map_or_else(|| exit_id.to_owned(), |(name, _)| name.clone()),
    };
    let routes = |state: &DesiredState| -> BTreeMap<String, String> {
        state
            .assignments
            .iter()
            .map(|assignment| (assignment.node_id.clone(), assignment.exit_id.clone()))
            .collect()
    };
    let (routes_before, routes_after) = (routes(before), routes(after));
    for (node, exit_id) in &routes_after {
        if routes_before.get(node) != Some(exit_id) {
            let name = device(node);
            changes.push((
                format!("Set the route of {name} to {}", route_label(exit_id)),
                Some(name),
            ));
        }
    }
    for node in routes_before.keys() {
        if !routes_after.contains_key(node) {
            let name = device(node);
            changes.push((
                format!("Reset the route of {name} to the default"),
                Some(name),
            ));
        }
    }

    let dns = |state: &DesiredState| -> BTreeMap<String, NodeDns> {
        state
            .dns
            .iter()
            .map(|setting| (setting.node_id.clone(), setting.clone()))
            .collect()
    };
    let (dns_before, dns_after) = (dns(before), dns(after));
    let nodes: std::collections::BTreeSet<&String> =
        dns_before.keys().chain(dns_after.keys()).collect();
    for node in nodes {
        let (old, new) = (dns_before.get(node), dns_after.get(node));
        if old == new {
            continue;
        }
        let name = device(node);
        let kill_switch = match new.and_then(|setting| setting.kill_switch) {
            Some(true) => "on",
            Some(false) => "off",
            None => "default",
        };
        let server = new
            .and_then(|setting| setting.server)
            .map_or_else(|| "default".to_owned(), |server| server.to_string());
        changes.push((
            format!("Changed DNS for {name}: kill switch {kill_switch}, server {server}"),
            Some(name),
        ));
    }
    changes
}

/// What a request that failed was trying to do, for the history.
pub fn attempted(method: &str, path: &str) -> String {
    let what = match (method, path.split('/').nth(2).unwrap_or_default()) {
        ("POST", "exits") => "add a location",
        ("PUT", "exits") => "change a location",
        ("DELETE", "exits") => "remove a location",
        (_, "assignments" | "routes") => "change a device's route",
        (_, "dns") => "change a device's DNS",
        ("POST", "custom-exits") => "import a WireGuard location",
        ("DELETE", "custom-exits") => "remove a WireGuard location",
        ("POST", "alerts") => "send a test alert",
        (_, "alerts") => "change alert settings",
        _ => return format!("{method} {path}"),
    };
    what.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Assignment, Exit, SCHEMA_VERSION};

    fn state(exits: &[(&str, &str, &str)], routes: &[(&str, &str)], dns: Vec<NodeDns>) -> Snapshot {
        Snapshot {
            desired: Some(DesiredState {
                schema_version: SCHEMA_VERSION,
                revision: 1,
                exits: exits
                    .iter()
                    .map(|(id, name, server)| Exit {
                        id: (*id).into(),
                        display_name: (*name).into(),
                        server_id: (*server).into(),
                        ..Exit::default()
                    })
                    .collect(),
                assignments: routes
                    .iter()
                    .map(|(node, exit)| Assignment {
                        node_id: (*node).into(),
                        exit_id: (*exit).into(),
                    })
                    .collect(),
                dns,
            }),
            imported: Vec::new(),
        }
    }

    fn lines(changes: Vec<(String, Option<String>)>) -> Vec<String> {
        changes.into_iter().map(|(line, _)| line).collect()
    }

    #[test]
    fn names_devices_and_locations() {
        let names = HashMap::from([("node-1".to_owned(), "envin-desktop".to_owned())]);
        let before = state(
            &[("exit-nl", "NL#227", "s-nl")],
            &[("node-1", "exit-nl")],
            vec![],
        );
        let after = state(
            &[("exit-es", "ES#146", "s-es")],
            &[("node-1", "exit-es"), ("node-2", DIRECT_ROUTE_ID)],
            vec![NodeDns {
                node_id: "node-1".into(),
                kill_switch: Some(false),
                server: None,
            }],
        );
        assert_eq!(
            lines(describe(&before, &after, &names)),
            [
                "Added location ES#146",
                "Removed location NL#227",
                "Set the route of envin-desktop to ES#146",
                "Set the route of node-2 to direct Internet",
                "Changed DNS for envin-desktop: kill switch off, server default",
            ]
        );
        assert_eq!(
            lines(describe(&after, &before, &names))[3],
            "Reset the route of node-2 to the default"
        );
        assert!(describe(&before, &before, &names).is_empty());
    }

    #[test]
    fn describes_failed_requests_by_intent() {
        assert_eq!(
            attempted("PUT", "/v1/routes/node-1"),
            "change a device's route"
        );
        assert_eq!(attempted("POST", "/v1/alerts/test"), "send a test alert");
        assert_eq!(attempted("PATCH", "/v1/other"), "PATCH /v1/other");
    }
}
