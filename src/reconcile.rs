use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::catalog::StaticCatalog;
use crate::domain::{Exit, ExitStatus, UnassignedPolicy};
use crate::platform::Runner;
use crate::policy::{self, MARK_MASK};
use crate::state::Store;
use crate::tailscale::Provider;
use crate::wireguard;

/// WireGuard renegotiates every two minutes while packets flow, and every tunnel
/// carries a persistent keepalive, so a handshake older than this means trouble.
const HEALTHY_HANDSHAKE_AGE: Duration = Duration::from_secs(180);
/// Beyond this the tunnel is torn down and recreated on the next reconcile.
const STALE_HANDSHAKE_AGE: Duration = Duration::from_secs(300);
/// How long a new tunnel may exist without any handshake before it is recreated.
const FIRST_HANDSHAKE_GRACE: Duration = Duration::from_secs(60);
/// How long a reconcile waits for a freshly created tunnel's first handshake.
const FIRST_HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Config {
    pub wan_interface: String,
    pub tailscale_interface: String,
    pub runtime_directory: PathBuf,
    pub dry_run: bool,
    pub unassigned: UnassignedPolicy,
}

#[derive(Default)]
struct Runtime {
    exits: Vec<Exit>,
    last_error: String,
    tunnels: HashMap<String, [u8; 32]>,
    slots: HashMap<String, u32>,
    created: HashMap<String, Instant>,
    applied_routes: BTreeMap<Ipv4Addr, String>,
    unknown_nodes: Vec<String>,
}

pub struct Reconciler {
    config: Config,
    store: Arc<Store>,
    catalog: Arc<StaticCatalog>,
    devices: Arc<Provider>,
    runner: Runner,
    runtime: Mutex<Runtime>,
}

#[derive(Debug, Eq, PartialEq)]
struct Verdict {
    status: ExitStatus,
    detail: String,
    rebuild: bool,
}

impl Reconciler {
    pub fn new(
        config: Config,
        store: Arc<Store>,
        catalog: Arc<StaticCatalog>,
        devices: Arc<Provider>,
        runner: Runner,
    ) -> Self {
        Self {
            config,
            store,
            catalog,
            devices,
            runner,
            runtime: Mutex::new(Runtime::default()),
        }
    }

    pub fn dry_run(&self) -> bool {
        self.config.dry_run
    }

    pub fn unassigned_policy(&self) -> UnassignedPolicy {
        self.config.unassigned
    }

    pub async fn install_baseline(&self) -> Result<()> {
        let compiled = policy::compile(policy::Input {
            wan_interface: &self.config.wan_interface,
            tailscale_interface: &self.config.tailscale_interface,
            exits: &[],
            devices: &[],
            assignments: &[],
            unassigned: UnassignedPolicy::Block,
        })?;
        self.apply_ruleset(&compiled.ruleset).await
    }

    pub async fn snapshot(&self) -> (Vec<Exit>, String) {
        let runtime = self.runtime.lock().await;
        (runtime.exits.clone(), runtime.last_error.clone())
    }

    pub async fn reconcile(&self) -> Result<()> {
        match self.reconcile_inner().await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.runtime.lock().await.last_error = error.to_string();
                Err(error)
            }
        }
    }

    async fn reconcile_inner(&self) -> Result<()> {
        let mut desired = self.store.load()?;
        let devices = match self.devices.devices().await {
            Ok(devices) => devices,
            Err(_) if self.config.dry_run => Vec::new(),
            Err(error) => return Err(error),
        };
        desired.exits.sort_by(|left, right| left.id.cmp(&right.id));
        let desired_ids: HashSet<_> = desired.exits.iter().map(|exit| exit.id.clone()).collect();

        let mut runtime = self.runtime.lock().await;
        self.remove_stale_tunnels(&mut runtime, &desired_ids).await;
        let mut runtime_exits = Vec::with_capacity(desired.exits.len());
        for mut wanted in desired.exits {
            let slot = allocate_slot(&mut runtime, &wanted.id)?;
            wanted.interface = format!("proton{slot}");
            wanted.mark = (slot + 1) << 8;
            wanted.table = 10_000 + slot;
            let verdict = match self.catalog.resolve(&wanted.server_id) {
                Err(error) => failed(format!("{error:#}")),
                Ok(server) => match self
                    .ensure_tunnel(&mut runtime, &wanted, &server.config_file)
                    .await
                {
                    Err(error) => failed(format!("{error:#}")),
                    Ok(()) => self.check_tunnel(&mut runtime, &wanted).await,
                },
            };
            if verdict.rebuild {
                // Dropping the fingerprint makes the next reconcile recreate the tunnel.
                runtime.tunnels.remove(&wanted.id);
            }
            if verdict.status != ExitStatus::Healthy {
                warn!(exit = %wanted.id, status = ?verdict.status, detail = %verdict.detail, "exit not healthy");
            }
            wanted.status = verdict.status;
            wanted.status_detail = verdict.detail;
            runtime_exits.push(wanted);
        }
        let compiled = policy::compile(policy::Input {
            wan_interface: &self.config.wan_interface,
            tailscale_interface: &self.config.tailscale_interface,
            exits: &runtime_exits,
            devices: &devices,
            assignments: &desired.assignments,
            unassigned: self.config.unassigned,
        })?;
        if compiled.unknown_nodes != runtime.unknown_nodes {
            if !compiled.unknown_nodes.is_empty() {
                warn!(
                    nodes = ?compiled.unknown_nodes,
                    "assignments reference nodes missing from the tailnet; they are ignored until the nodes return"
                );
            }
            runtime.unknown_nodes = compiled.unknown_nodes;
        }
        self.apply_ruleset(&compiled.ruleset).await?;
        self.reset_moved_connections(&runtime.applied_routes, &compiled.routes)
            .await;
        runtime.applied_routes = compiled.routes;
        runtime.exits = runtime_exits;
        runtime.last_error.clear();
        Ok(())
    }

    async fn ensure_tunnel(
        &self,
        runtime: &mut Runtime,
        exit: &Exit,
        config_path: &str,
    ) -> Result<()> {
        let configuration = wireguard::parse_file(config_path)?;
        let mut hasher = Sha256::new();
        hasher.update(configuration.set_conf.as_bytes());
        for (address, prefix) in &configuration.addresses {
            hasher.update(address.octets());
            hasher.update([*prefix]);
        }
        hasher.update(exit.interface.as_bytes());
        hasher.update(exit.mark.to_be_bytes());
        hasher.update(exit.table.to_be_bytes());
        let fingerprint: [u8; 32] = hasher.finalize().into();
        if runtime.tunnels.get(&exit.id) == Some(&fingerprint) {
            if self.config.dry_run || self.interface_up(&exit.interface).await {
                return Ok(());
            }
            warn!(exit = %exit.id, interface = %exit.interface, "tunnel interface missing or down; recreating");
        }
        if self.config.dry_run {
            runtime.tunnels.insert(exit.id.clone(), fingerprint);
            runtime.created.insert(exit.id.clone(), Instant::now());
            return Ok(());
        }
        fs::create_dir_all(&self.config.runtime_directory)?;
        let set_conf_path = self
            .config
            .runtime_directory
            .join(format!("{}.conf", exit.interface));
        fs::write(&set_conf_path, configuration.set_conf.as_bytes())?;
        set_private_permissions(&set_conf_path)?;
        let _ = self
            .runner
            .run("ip", ["link", "delete", &exit.interface])
            .await;
        let mut commands = vec![
            vec![
                "link".into(),
                "add".into(),
                exit.interface.clone(),
                "type".into(),
                "wireguard".into(),
            ],
            vec![
                "__wg__".into(),
                "setconf".into(),
                exit.interface.clone(),
                set_conf_path.to_string_lossy().into_owned(),
            ],
        ];
        for (address, prefix) in configuration.addresses {
            commands.push(vec![
                "address".into(),
                "add".into(),
                format!("{address}/{prefix}"),
                "dev".into(),
                exit.interface.clone(),
            ]);
        }
        commands.push(vec![
            "link".into(),
            "set".into(),
            "up".into(),
            "dev".into(),
            exit.interface.clone(),
        ]);
        commands.push(vec![
            "route".into(),
            "replace".into(),
            "default".into(),
            "dev".into(),
            exit.interface.clone(),
            "table".into(),
            exit.table.to_string(),
        ]);
        let mark = format!("{:#x}/{:#x}", exit.mark, MARK_MASK);
        let table = exit.table.to_string();
        let _ = self
            .runner
            .run("ip", ["rule", "del", "fwmark", &mark, "table", &table])
            .await;
        commands.push(vec![
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            mark,
            "table".into(),
            table,
            "priority".into(),
            (11_000 + exit.table - 10_000).to_string(),
        ]);
        let result = self.run_commands(commands, &exit.interface).await;
        // The kernel holds its own copy of the key; do not leave it on disk.
        let _ = fs::remove_file(&set_conf_path);
        result?;
        runtime.tunnels.insert(exit.id.clone(), fingerprint);
        runtime.created.insert(exit.id.clone(), Instant::now());
        Ok(())
    }

    async fn run_commands(&self, commands: Vec<Vec<String>>, interface: &str) -> Result<()> {
        for mut command in commands {
            let program = if command.first().map(String::as_str) == Some("__wg__") {
                command.remove(0);
                "wg"
            } else {
                "ip"
            };
            if let Err(error) = self.runner.run(program, &command).await {
                let _ = self.runner.run("ip", ["link", "delete", interface]).await;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn interface_up(&self, interface: &str) -> bool {
        match self
            .runner
            .run("ip", ["-o", "link", "show", "dev", interface])
            .await
        {
            Ok(output) => link_is_up(&String::from_utf8_lossy(&output)),
            Err(_) => false,
        }
    }

    async fn latest_handshake(&self, interface: &str) -> Result<Option<u64>> {
        let output = self
            .runner
            .run("wg", ["show", interface, "latest-handshakes"])
            .await?;
        parse_latest_handshake(&String::from_utf8_lossy(&output))
    }

    async fn check_tunnel(&self, runtime: &mut Runtime, exit: &Exit) -> Verdict {
        if self.config.dry_run {
            return Verdict {
                status: ExitStatus::Healthy,
                detail: String::new(),
                rebuild: false,
            };
        }
        let since_created = runtime
            .created
            .get(&exit.id)
            .map_or(Duration::MAX, Instant::elapsed);
        let mut handshake = self.latest_handshake(&exit.interface).await;
        if since_created < FIRST_HANDSHAKE_WAIT {
            let deadline = Instant::now() + FIRST_HANDSHAKE_WAIT;
            while matches!(handshake, Ok(None)) && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(250)).await;
                handshake = self.latest_handshake(&exit.interface).await;
            }
        }
        match handshake {
            Err(error) => Verdict {
                status: ExitStatus::Failed,
                detail: format!("cannot read tunnel state: {error:#}; recreating"),
                rebuild: true,
            },
            Ok(latest) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age = latest.map(|seconds| Duration::from_secs(now.saturating_sub(seconds)));
                classify(
                    age,
                    runtime
                        .created
                        .get(&exit.id)
                        .map_or(Duration::MAX, Instant::elapsed),
                )
            }
        }
    }

    /// Existing conntrack entries keep the NAT and mark chosen for the old route, so a
    /// moved device would keep using it until each flow ends. Drop them instead.
    async fn reset_moved_connections(
        &self,
        previous: &BTreeMap<Ipv4Addr, String>,
        current: &BTreeMap<Ipv4Addr, String>,
    ) {
        if self.config.dry_run {
            return;
        }
        for address in moved_addresses(previous, current) {
            let source = address.to_string();
            // conntrack exits non-zero when no entry matched; that is fine.
            let _ = self
                .runner
                .run("conntrack", ["-D", "-f", "ipv4", "-s", &source])
                .await;
            info!(address = %source, route = current.get(&address).map_or("removed", String::as_str), "route changed; reset tracked connections");
        }
    }

    async fn remove_stale_tunnels(&self, runtime: &mut Runtime, desired_ids: &HashSet<String>) {
        let stale: BTreeMap<_, _> = runtime
            .slots
            .iter()
            .filter(|(exit_id, _)| !desired_ids.contains(*exit_id))
            .map(|(exit_id, slot)| (exit_id.clone(), *slot))
            .collect();
        for (exit_id, slot) in stale {
            if !self.config.dry_run {
                let interface = format!("proton{slot}");
                let mark = format!("{:#x}/{:#x}", (slot + 1) << 8, MARK_MASK);
                let table = (10_000 + slot).to_string();
                let _ = self
                    .runner
                    .run("ip", ["rule", "del", "fwmark", &mark, "table", &table])
                    .await;
                let _ = self
                    .runner
                    .run("ip", ["route", "flush", "table", &table])
                    .await;
                let _ = self.runner.run("ip", ["link", "delete", &interface]).await;
            }
            runtime.slots.remove(&exit_id);
            runtime.tunnels.remove(&exit_id);
            runtime.created.remove(&exit_id);
        }
    }

    async fn apply_ruleset(&self, ruleset: &str) -> Result<()> {
        fs::create_dir_all(&self.config.runtime_directory)?;
        let path = self.config.runtime_directory.join("policy.nft");
        fs::write(&path, ruleset).context("write compiled nftables ruleset")?;
        set_private_permissions(&path)?;
        if self.config.dry_run {
            return Ok(());
        }
        let path = path.to_string_lossy().into_owned();
        self.runner.run("nft", ["-c", "-f", &path]).await?;
        self.runner.run("nft", ["-f", &path]).await?;
        Ok(())
    }
}

fn failed(detail: String) -> Verdict {
    Verdict {
        status: ExitStatus::Failed,
        detail,
        rebuild: false,
    }
}

fn classify(handshake_age: Option<Duration>, since_created: Duration) -> Verdict {
    let verdict = |status, detail: String, rebuild| Verdict {
        status,
        detail,
        rebuild,
    };
    match handshake_age {
        Some(age) if age <= HEALTHY_HANDSHAKE_AGE => {
            verdict(ExitStatus::Healthy, String::new(), false)
        }
        Some(age) if age <= STALE_HANDSHAKE_AGE => verdict(
            ExitStatus::Degraded,
            format!("last handshake {}s ago", age.as_secs()),
            false,
        ),
        Some(age) => verdict(
            ExitStatus::Failed,
            format!("no handshake for {}s; recreating", age.as_secs()),
            true,
        ),
        None if since_created <= FIRST_HANDSHAKE_GRACE => verdict(
            ExitStatus::Pending,
            "waiting for first handshake".into(),
            false,
        ),
        None => verdict(
            ExitStatus::Failed,
            "no handshake since the tunnel was created; recreating".into(),
            true,
        ),
    }
}

fn parse_latest_handshake(output: &str) -> Result<Option<u64>> {
    let mut latest = None;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let Some(seconds) = line.split_whitespace().nth(1) else {
            bail!("unexpected wg latest-handshakes output");
        };
        let seconds: u64 = seconds
            .parse()
            .context("unexpected wg latest-handshakes output")?;
        if seconds > 0 {
            latest = latest.max(Some(seconds));
        }
    }
    Ok(latest)
}

fn link_is_up(output: &str) -> bool {
    output
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"))
}

fn moved_addresses(
    previous: &BTreeMap<Ipv4Addr, String>,
    current: &BTreeMap<Ipv4Addr, String>,
) -> Vec<Ipv4Addr> {
    previous
        .iter()
        .filter(|(address, route)| current.get(*address) != Some(*route))
        .map(|(address, _)| *address)
        .collect()
}

fn allocate_slot(runtime: &mut Runtime, exit_id: &str) -> Result<u32> {
    if let Some(slot) = runtime.slots.get(exit_id) {
        return Ok(*slot);
    }
    for slot in 0..255 {
        if !runtime.slots.values().any(|candidate| *candidate == slot) {
            runtime.slots.insert(exit_id.into(), slot);
            return Ok(slot);
        }
    }
    bail!("no runtime exit slot available")
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_all_supported_runtime_exit_slots() {
        let mut runtime = Runtime::default();
        for slot in 0..255 {
            assert_eq!(
                allocate_slot(&mut runtime, &format!("exit-{slot}")).unwrap(),
                slot
            );
        }
        assert!(allocate_slot(&mut runtime, "exit-overflow").is_err());
    }

    #[test]
    fn classifies_tunnel_health_from_handshake_age() {
        let secs = Duration::from_secs;
        assert_eq!(
            classify(Some(secs(30)), secs(600)).status,
            ExitStatus::Healthy
        );
        let degraded = classify(Some(secs(240)), secs(600));
        assert_eq!(degraded.status, ExitStatus::Degraded);
        assert!(!degraded.rebuild);
        let stale = classify(Some(secs(900)), secs(1200));
        assert_eq!(stale.status, ExitStatus::Failed);
        assert!(stale.rebuild);
        assert_eq!(classify(None, secs(10)).status, ExitStatus::Pending);
        let never = classify(None, secs(120));
        assert_eq!(never.status, ExitStatus::Failed);
        assert!(never.rebuild);
    }

    #[test]
    fn parses_latest_handshakes() {
        assert_eq!(
            parse_latest_handshake("key=\t1790254596\n").unwrap(),
            Some(1_790_254_596)
        );
        assert_eq!(parse_latest_handshake("key=\t0\n").unwrap(), None);
        assert_eq!(parse_latest_handshake("").unwrap(), None);
        assert!(parse_latest_handshake("garbage\n").is_err());
    }

    #[test]
    fn detects_link_state() {
        assert!(link_is_up(
            "4: proton0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN"
        ));
        assert!(!link_is_up(
            "4: proton0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN"
        ));
        assert!(!link_is_up(""));
    }

    #[test]
    fn finds_addresses_whose_route_changed() {
        let a = Ipv4Addr::new(100, 64, 0, 10);
        let b = Ipv4Addr::new(100, 64, 0, 11);
        let c = Ipv4Addr::new(100, 64, 0, 12);
        let previous = BTreeMap::from([
            (a, "direct".to_owned()),
            (b, "exit:one".to_owned()),
            (c, "local".to_owned()),
        ]);
        let current = BTreeMap::from([(a, "direct".to_owned()), (b, "exit:two".to_owned())]);
        assert_eq!(moved_addresses(&previous, &current), vec![b, c]);
    }
}
