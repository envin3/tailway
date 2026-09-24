use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;
use std::net::Ipv4Addr;

use anyhow::{Result, bail};

use crate::domain::{Assignment, Device, Exit, ExitStatus, LOCAL_ROUTE_ID};

pub const MARK_MASK: u32 = 0x0000_ff00;

pub struct Input<'a> {
    pub wan_interface: &'a str,
    pub tailscale_interface: &'a str,
    pub exits: &'a [Exit],
    pub devices: &'a [Device],
    pub assignments: &'a [Assignment],
}

pub fn compile(input: Input<'_>) -> Result<String> {
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
        if exit.status != ExitStatus::Healthy {
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

    let mut devices = HashMap::new();
    for device in input.devices {
        if device.node_id.is_empty() {
            bail!("device has empty node ID");
        }
        if devices.insert(device.node_id.clone(), device).is_some() {
            bail!("duplicate node ID {:?}", device.node_id);
        }
    }

    let mut vpn_bindings = BTreeMap::<Ipv4Addr, &Exit>::new();
    let mut direct_addresses = Vec::<Ipv4Addr>::new();
    let mut local_addresses = Vec::<Ipv4Addr>::new();
    let mut seen_nodes = HashSet::new();
    let mut address_owners = BTreeMap::<Ipv4Addr, &str>::new();
    let assignments = input
        .assignments
        .iter()
        .map(|assignment| (assignment.node_id.as_str(), assignment))
        .collect::<HashMap<_, _>>();
    if assignments.len() != input.assignments.len() {
        bail!("duplicate node assignment");
    }
    for device in input.devices {
        let assignment = assignments.get(device.node_id.as_str()).copied();
        if let Some(assignment) = assignment
            && assignment.exit_id != LOCAL_ROUTE_ID
            && !known_exit_ids.contains(&assignment.exit_id)
        {
            bail!(
                "assignment references unknown exit {:?}",
                assignment.exit_id
            );
        }
        for address in &device.addresses {
            let std::net::IpAddr::V4(address) = address else {
                continue;
            };
            match assignment {
                None => direct_addresses.push(*address),
                Some(assignment) if assignment.exit_id == LOCAL_ROUTE_ID => {
                    local_addresses.push(*address)
                }
                Some(assignment) => {
                    if let Some(exit) = exits.get(&assignment.exit_id) {
                        vpn_bindings.insert(*address, exit);
                    }
                }
            }
        }
    }
    for assignment in input.assignments {
        if !seen_nodes.insert(&assignment.node_id) {
            bail!("duplicate assignment for node {:?}", assignment.node_id);
        }
        let Some(device) = devices.get(&assignment.node_id) else {
            bail!(
                "assignment references unknown node {:?}",
                assignment.node_id
            );
        };
        if assignment.exit_id == LOCAL_ROUTE_ID {
            continue;
        }
        let exit = exits.get(&assignment.exit_id);
        for address in &device.addresses {
            let std::net::IpAddr::V4(address) = address else {
                continue;
            };
            if let Some(owner) = address_owners.get(address)
                && *owner != assignment.node_id
            {
                bail!("address {address} belongs to multiple nodes");
            }
            address_owners.insert(*address, &assignment.node_id);
            if let Some(exit) = exit {
                vpn_bindings.insert(*address, exit);
            }
        }
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
    Ok(output)
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

    #[test]
    fn compile_route_modes_policy() {
        let healthy_exit = Exit {
            id: "exit-ch".into(),
            interface: "proton0".into(),
            mark: 0x0000_0100,
            status: ExitStatus::Healthy,
            ..Exit::default()
        };
        let devices = vec![
            Device {
                node_id: "node-a".into(),
                display_name: String::new(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))],
                online: true,
                active: true,
            },
            Device {
                node_id: "node-b".into(),
                display_name: String::new(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11))],
                online: true,
                active: true,
            },
            Device {
                node_id: "node-c".into(),
                display_name: String::new(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 12))],
                online: true,
                active: true,
            },
        ];
        let assignments = vec![
            Assignment {
                node_id: "node-a".into(),
                exit_id: "exit-ch".into(),
            },
            Assignment {
                node_id: "node-c".into(),
                exit_id: LOCAL_ROUTE_ID.into(),
            },
        ];
        let exits = vec![healthy_exit];

        let ruleset = compile(Input {
            wan_interface: "eth0",
            tailscale_interface: "tailscale0",
            exits: &exits,
            devices: &devices,
            assignments: &assignments,
        })
        .unwrap();

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
                ruleset.contains(fragment),
                "ruleset missing {fragment:?}\n{ruleset}"
            );
        }
    }

    #[test]
    fn blocks_an_assignment_to_an_unavailable_exit() {
        let exits = vec![Exit {
            id: "exit-ch".into(),
            interface: "proton0".into(),
            mark: 0x100,
            status: ExitStatus::Failed,
            ..Exit::default()
        }];
        let devices = vec![Device {
            node_id: "node-a".into(),
            display_name: String::new(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))],
            online: true,
            active: true,
        }];
        let assignments = vec![Assignment {
            node_id: "node-a".into(),
            exit_id: "exit-ch".into(),
        }];
        let ruleset = compile(Input {
            wan_interface: "eth0",
            tailscale_interface: "tailscale0",
            exits: &exits,
            devices: &devices,
            assignments: &assignments,
        })
        .unwrap();
        assert!(!ruleset.contains("ip saddr 100.64.0.10 oifname \"eth0\" accept"));
        assert!(ruleset.contains("iifname \"tailscale0\" reject"));
    }
}
