use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write;
use std::net::Ipv4Addr;

use anyhow::{Result, bail};

use crate::domain::{
    Assignment, DIRECT_ROUTE_ID, Device, Exit, ExitStatus, LOCAL_ROUTE_ID, UnassignedPolicy,
};

pub const MARK_MASK: u32 = 0x0000_ff00;

pub struct Input<'a> {
    pub wan_interface: &'a str,
    pub tailscale_interface: &'a str,
    pub exits: &'a [Exit],
    pub devices: &'a [Device],
    pub assignments: &'a [Assignment],
    pub unassigned: UnassignedPolicy,
    /// Redirect DNS sent to the gateway's own tailnet address to this local port.
    pub dns_port: Option<u16>,
}

pub struct Compiled {
    pub ruleset: String,
    /// Route key applied to each forwarded source address: `block`, `local`,
    /// `direct`, or `exit:<id>`.
    pub routes: BTreeMap<Ipv4Addr, String>,
    /// Assigned node IDs that are not present in the current Tailscale peer list.
    pub unknown_nodes: Vec<String>,
}

#[derive(Clone, Copy)]
enum Route<'a> {
    Block,
    Local,
    Direct,
    Vpn(&'a Exit),
}

impl Route<'_> {
    fn key(self) -> String {
        match self {
            Route::Block => "block".into(),
            Route::Local => "local".into(),
            Route::Direct => "direct".into(),
            Route::Vpn(exit) => format!("exit:{}", exit.id),
        }
    }
}

/// Only these exits carry traffic. A degraded exit still has a tunnel, so traffic
/// stays inside it (and is dropped there) rather than falling back to the WAN.
pub fn routable(status: &ExitStatus) -> bool {
    matches!(status, ExitStatus::Healthy | ExitStatus::Degraded)
}

pub fn compile(input: Input<'_>) -> Result<Compiled> {
    if !valid_interface(input.wan_interface) || !valid_interface(input.tailscale_interface) {
        bail!("invalid WAN or Tailscale interface");
    }

    let mut exits = BTreeMap::new();
    let mut known_exit_ids = HashSet::new();
    let mut marks = HashSet::new();
    let mut interfaces = HashSet::new();
    for exit in input.exits {
        if exit.id.is_empty()
            || !valid_interface(&exit.interface)
            || exit.mark & !MARK_MASK != 0
            || exit.mark == 0
        {
            bail!("invalid exit {:?}", exit.id);
        }
        if !known_exit_ids.insert(exit.id.clone()) {
            bail!("duplicate exit ID {:?}", exit.id);
        }
        if !routable(&exit.status) {
            continue;
        }
        if !marks.insert(exit.mark) {
            bail!("duplicate exit mark {:#x}", exit.mark);
        }
        if !interfaces.insert(exit.interface.clone()) {
            bail!("duplicate exit interface {:?}", exit.interface);
        }
        exits.insert(exit.id.clone(), exit);
    }

    let mut device_ids = HashSet::new();
    for device in input.devices {
        if device.node_id.is_empty() {
            bail!("device has empty node ID");
        }
        if !device_ids.insert(device.node_id.as_str()) {
            bail!("duplicate node ID {:?}", device.node_id);
        }
    }

    let assignments = input
        .assignments
        .iter()
        .map(|assignment| (assignment.node_id.as_str(), assignment))
        .collect::<HashMap<_, _>>();
    if assignments.len() != input.assignments.len() {
        bail!("duplicate node assignment");
    }
    // A node removed from the tailnet keeps its stored assignment so it resumes
    // the same route if it rejoins; it must not block routing for everyone else.
    let unknown_nodes = assignments
        .keys()
        .filter(|node_id| !device_ids.contains(*node_id))
        .map(|node_id| (*node_id).to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut owners = BTreeMap::<Ipv4Addr, (&str, Route)>::new();
    let mut conflicts = BTreeSet::<Ipv4Addr>::new();
    for device in input.devices {
        let route = match assignments.get(device.node_id.as_str()) {
            None => match input.unassigned {
                UnassignedPolicy::Block => Route::Block,
                UnassignedPolicy::Local => Route::Local,
                UnassignedPolicy::Direct => Route::Direct,
            },
            Some(assignment) if assignment.exit_id == LOCAL_ROUTE_ID => Route::Local,
            Some(assignment) if assignment.exit_id == DIRECT_ROUTE_ID => Route::Direct,
            // Unknown or unhealthy exits fail closed for this device only.
            Some(assignment) => exits
                .get(&assignment.exit_id)
                .map_or(Route::Block, |exit| Route::Vpn(exit)),
        };
        for address in &device.addresses {
            let std::net::IpAddr::V4(address) = address else {
                continue;
            };
            if let Some((owner, _)) = owners.get(address)
                && *owner != device.node_id
            {
                conflicts.insert(*address);
            }
            owners.insert(*address, (&device.node_id, route));
        }
    }

    let mut routes = BTreeMap::new();
    let mut vpn_bindings = BTreeMap::<Ipv4Addr, &Exit>::new();
    let mut direct_addresses = Vec::<Ipv4Addr>::new();
    let mut local_addresses = Vec::<Ipv4Addr>::new();
    for (address, (_, route)) in owners {
        // An address claimed by two peers is ambiguous; forward nothing for it.
        let route = if conflicts.contains(&address) {
            Route::Block
        } else {
            route
        };
        match route {
            Route::Block => {}
            Route::Local => local_addresses.push(address),
            Route::Direct => direct_addresses.push(address),
            Route::Vpn(exit) => {
                vpn_bindings.insert(address, exit);
            }
        }
        routes.insert(address, route.key());
    }

    let inverse_mask = !MARK_MASK;
    let mut output = String::new();
    writeln!(output, "table inet tailscale_exit_policy_router")?;
    writeln!(output, "flush table inet tailscale_exit_policy_router")?;
    writeln!(output, "table inet tailscale_exit_policy_router {{")?;
    writeln!(output, "  chain forward {{")?;
    writeln!(
        output,
        "    type filter hook forward priority filter; policy drop;"
    )?;
    writeln!(
        output,
        "    ct state established,related iifname != {:?} oifname {:?} accept",
        input.tailscale_interface, input.tailscale_interface
    )?;
    for exit in exits.values() {
        writeln!(
            output,
            "    iifname {:?} oifname {:?} ct mark & 0x{MARK_MASK:08x} == 0x{:08x} accept",
            input.tailscale_interface, exit.interface, exit.mark
        )?;
    }
    for address in &local_addresses {
        writeln!(
            output,
            "    iifname {:?} ip saddr {address} ip daddr {{ 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 }} oifname {:?} accept",
            input.tailscale_interface, input.wan_interface
        )?;
        writeln!(
            output,
            "    iifname {:?} ip saddr {address} oifname {:?} reject with icmpx type admin-prohibited",
            input.tailscale_interface, input.wan_interface
        )?;
    }
    for address in &direct_addresses {
        writeln!(
            output,
            "    iifname {:?} ip saddr {address} oifname {:?} accept",
            input.tailscale_interface, input.wan_interface
        )?;
    }
    writeln!(
        output,
        "    iifname {:?} reject with icmpx type admin-prohibited\n  }}",
        input.tailscale_interface
    )?;
    writeln!(output, "  chain classify {{")?;
    writeln!(
        output,
        "    type filter hook prerouting priority mangle; policy accept;"
    )?;
    for (address, exit) in vpn_bindings {
        writeln!(
            output,
            "    iifname {:?} ip saddr {address} ct mark set (ct mark & 0x{inverse_mask:08x}) | 0x{:08x} meta mark set (meta mark & 0x{inverse_mask:08x}) | 0x{:08x}",
            input.tailscale_interface, exit.mark, exit.mark
        )?;
    }
    writeln!(output, "  }}")?;
    if let Some(port) = input.dns_port {
        // Only queries addressed to the gateway itself; forwarded DNS to other
        // resolvers is routed like any other traffic.
        writeln!(output, "  chain dns_redirect {{")?;
        writeln!(
            output,
            "    type nat hook prerouting priority dstnat; policy accept;"
        )?;
        writeln!(
            output,
            "    iifname {:?} fib daddr type local meta l4proto {{ tcp, udp }} th dport 53 redirect to :{port}",
            input.tailscale_interface
        )?;
        writeln!(output, "  }}")?;
    }
    writeln!(output, "  chain postrouting {{")?;
    writeln!(
        output,
        "    type nat hook postrouting priority srcnat; policy accept;"
    )?;
    for exit in exits.values() {
        writeln!(
            output,
            "    oifname {:?} ct mark & 0x{MARK_MASK:08x} == 0x{:08x} masquerade",
            exit.interface, exit.mark
        )?;
    }
    for address in direct_addresses.iter().chain(&local_addresses) {
        writeln!(
            output,
            "    oifname {:?} ip saddr {address} masquerade",
            input.wan_interface
        )?;
    }
    writeln!(output, "  }}\n}}")?;
    Ok(Compiled {
        ruleset: output,
        routes,
        unknown_nodes,
    })
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || b"_-.".contains(&character))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::domain::{Assignment, Device, Exit};

    fn device(node_id: &str, last_octet: u8) -> Device {
        Device {
            node_id: node_id.into(),
            display_name: String::new(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, last_octet))],
            online: true,
            active: true,
        }
    }

    fn assign(node_id: &str, exit_id: &str) -> Assignment {
        Assignment {
            node_id: node_id.into(),
            exit_id: exit_id.into(),
        }
    }

    fn exit(id: &str, status: ExitStatus) -> Exit {
        Exit {
            id: id.into(),
            interface: "proton0".into(),
            mark: 0x0000_0100,
            status,
            ..Exit::default()
        }
    }

    fn compile_with(
        exits: &[Exit],
        devices: &[Device],
        assignments: &[Assignment],
        unassigned: UnassignedPolicy,
    ) -> Compiled {
        compile(Input {
            wan_interface: "eth0",
            tailscale_interface: "tailscale0",
            exits,
            devices,
            assignments,
            unassigned,
            dns_port: None,
        })
        .unwrap()
    }

    #[test]
    fn redirects_dns_for_the_gateway_only_when_enabled() {
        let compiled = compile(Input {
            wan_interface: "eth0",
            tailscale_interface: "tailscale0",
            exits: &[],
            devices: &[],
            assignments: &[],
            unassigned: UnassignedPolicy::Block,
            dns_port: Some(5353),
        })
        .unwrap();
        assert!(compiled.ruleset.contains(
            "iifname \"tailscale0\" fib daddr type local meta l4proto { tcp, udp } th dport 53 redirect to :5353"
        ));
        let disabled = compile_with(&[], &[], &[], UnassignedPolicy::Block);
        assert!(!disabled.ruleset.contains("dns_redirect"));
    }

    #[test]
    fn compile_route_modes_policy() {
        let devices = vec![
            device("node-a", 10),
            device("node-b", 11),
            device("node-c", 12),
        ];
        let assignments = vec![
            assign("node-a", "exit-ch"),
            assign("node-b", DIRECT_ROUTE_ID),
            assign("node-c", LOCAL_ROUTE_ID),
        ];
        let exits = vec![exit("exit-ch", ExitStatus::Healthy)];
        let compiled = compile_with(&exits, &devices, &assignments, UnassignedPolicy::Block);

        for fragment in [
            "policy drop",
            "ip saddr 100.64.0.10 ct mark set",
            "ct mark set (ct mark & 0xffff00ff) | 0x00000100",
            "ip saddr 100.64.0.11 oifname \"eth0\" accept",
            "oifname \"eth0\" ip saddr 100.64.0.11 masquerade",
            "ip saddr 100.64.0.12 ip daddr { 10.0.0.0/8",
            "ip saddr 100.64.0.12 oifname \"eth0\" reject",
            "iifname \"tailscale0\" reject",
            "oifname \"proton0\" ct mark & 0x0000ff00 == 0x00000100 masquerade",
        ] {
            assert!(
                compiled.ruleset.contains(fragment),
                "ruleset missing {fragment:?}\n{}",
                compiled.ruleset
            );
        }
        assert_eq!(
            compiled.routes[&Ipv4Addr::new(100, 64, 0, 10)],
            "exit:exit-ch"
        );
        assert_eq!(compiled.routes[&Ipv4Addr::new(100, 64, 0, 11)], "direct");
        assert_eq!(compiled.routes[&Ipv4Addr::new(100, 64, 0, 12)], "local");
    }

    #[test]
    fn blocks_an_assignment_to_an_unavailable_exit() {
        let exits = vec![exit("exit-ch", ExitStatus::Failed)];
        let devices = vec![device("node-a", 10)];
        let assignments = vec![assign("node-a", "exit-ch")];
        let compiled = compile_with(&exits, &devices, &assignments, UnassignedPolicy::Direct);
        assert!(!compiled.ruleset.contains("ip saddr 100.64.0.10"));
        assert!(compiled.ruleset.contains("iifname \"tailscale0\" reject"));
        assert_eq!(compiled.routes[&Ipv4Addr::new(100, 64, 0, 10)], "block");
    }

    #[test]
    fn degraded_exit_keeps_traffic_in_its_tunnel() {
        let exits = vec![exit("exit-ch", ExitStatus::Degraded)];
        let devices = vec![device("node-a", 10)];
        let assignments = vec![assign("node-a", "exit-ch")];
        let compiled = compile_with(&exits, &devices, &assignments, UnassignedPolicy::Direct);
        assert!(
            compiled
                .ruleset
                .contains("ip saddr 100.64.0.10 ct mark set")
        );
        assert!(
            !compiled
                .ruleset
                .contains("ip saddr 100.64.0.10 oifname \"eth0\"")
        );
    }

    #[test]
    fn assignment_to_unknown_exit_blocks_only_that_device() {
        let devices = vec![device("node-a", 10), device("node-b", 11)];
        let assignments = vec![
            assign("node-a", "exit-gone"),
            assign("node-b", DIRECT_ROUTE_ID),
        ];
        let compiled = compile_with(&[], &devices, &assignments, UnassignedPolicy::Block);
        assert!(!compiled.ruleset.contains("ip saddr 100.64.0.10"));
        assert!(
            compiled
                .ruleset
                .contains("ip saddr 100.64.0.11 oifname \"eth0\" accept")
        );
    }

    #[test]
    fn stale_node_assignment_does_not_break_other_devices() {
        let devices = vec![device("node-a", 10)];
        let assignments = vec![
            assign("node-removed", LOCAL_ROUTE_ID),
            assign("node-a", DIRECT_ROUTE_ID),
        ];
        let compiled = compile_with(&[], &devices, &assignments, UnassignedPolicy::Block);
        assert!(
            compiled
                .ruleset
                .contains("ip saddr 100.64.0.10 oifname \"eth0\" accept")
        );
        assert_eq!(compiled.unknown_nodes, vec!["node-removed".to_owned()]);
    }

    #[test]
    fn unassigned_policy_controls_unassigned_devices() {
        let devices = vec![device("node-a", 10)];
        let blocked = compile_with(&[], &devices, &[], UnassignedPolicy::Block);
        assert!(!blocked.ruleset.contains("ip saddr 100.64.0.10"));
        assert_eq!(blocked.routes[&Ipv4Addr::new(100, 64, 0, 10)], "block");

        let local = compile_with(&[], &devices, &[], UnassignedPolicy::Local);
        assert!(
            local
                .ruleset
                .contains("ip saddr 100.64.0.10 ip daddr { 10.0.0.0/8")
        );

        let direct = compile_with(&[], &devices, &[], UnassignedPolicy::Direct);
        assert!(
            direct
                .ruleset
                .contains("ip saddr 100.64.0.10 oifname \"eth0\" accept")
        );
    }

    #[test]
    fn address_claimed_by_two_nodes_is_blocked() {
        let devices = vec![device("node-a", 10), device("node-b", 10)];
        let assignments = vec![
            assign("node-a", DIRECT_ROUTE_ID),
            assign("node-b", DIRECT_ROUTE_ID),
        ];
        let compiled = compile_with(&[], &devices, &assignments, UnassignedPolicy::Direct);
        assert!(!compiled.ruleset.contains("ip saddr 100.64.0.10"));
        assert_eq!(compiled.routes[&Ipv4Addr::new(100, 64, 0, 10)], "block");
    }
}
