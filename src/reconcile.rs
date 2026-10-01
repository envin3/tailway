use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::catalog::StaticCatalog;
use crate::dns;
use crate::domain::{Exit, ExitStatus, UnassignedPolicy, is_builtin_route};
use crate::events::EventLog;
use crate::exit_watch::DeviceUse;
use crate::history;
use crate::metrics::{ExitSample, Metrics};
use crate::platform::Runner;
use crate::policy::{self, MARK_MASK};
use crate::probe;
use crate::state::Store;
use crate::tailscale::Provider;
use crate::usage;
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
/// Consecutive failed traffic probes before an exit counts as failed (one probe
/// per reconcile, so about a minute at the default interval).
const PROBE_FAILURE_LIMIT: u32 = 2;
/// While probes keep failing, recreate the tunnel this often (in probes) rather
/// than on every reconcile: a rebuild cannot fix an invalid certificate.
const PROBE_REBUILD_EVERY: u32 = 10;

#[derive(Clone)]
pub struct Config {
    pub wan_interface: String,
    pub tailscale_interface: String,
    pub runtime_directory: PathBuf,
    pub dry_run: bool,
    pub unassigned: UnassignedPolicy,
    pub dns: Option<DnsConfig>,
}

#[derive(Clone, Copy)]
pub struct DnsConfig {
    pub defaults: dns::Defaults,
    /// Local port the forwarder listens on; tailnet port 53 is redirected here.
    pub port: u16,
}

#[derive(Default)]
struct Runtime {
    tunnels: HashMap<String, [u8; 32]>,
    slots: HashMap<String, u32>,
    created: HashMap<String, Instant>,
    applied_routes: BTreeMap<Ipv4Addr, String>,
    unknown_nodes: Vec<String>,
    applied_revision: Option<u64>,
    probes: HashMap<String, ProbeState>,
    /// Each location's last state in the event history.
    recorded: HashMap<String, history::Recorded>,
}

#[derive(Default)]
struct ProbeState {
    egress_failures: u32,
    resolver_failures: u32,
    public_ip: Option<Ipv4Addr>,
    /// Round trip of the last successful probe.
    round_trip: Option<Duration>,
}

/// Last reconcile outcome, readable without waiting for a reconcile in progress.
#[derive(Clone, Default)]
struct Published {
    exits: Vec<Exit>,
    last_error: String,
    applied_revision: Option<u64>,
    tailscale_running: bool,
}

pub struct Reconciler {
    config: Config,
    store: Arc<Store>,
    catalog: Arc<StaticCatalog>,
    devices: Arc<Provider>,
    runner: Runner,
    runtime: Mutex<Runtime>,
    published: std::sync::Mutex<Published>,
    dns: Option<Arc<dns::Resolver>>,
    events: Option<Arc<EventLog>>,
    metrics: Option<Arc<Metrics>>,
    /// When the last reconcile pass finished, successful or not (liveness).
    last_pass: std::sync::Mutex<Instant>,
}

#[derive(Debug, Eq, PartialEq)]
struct Verdict {
    status: ExitStatus,
    detail: String,
    rebuild: bool,
    /// Why, as a stable code (see `Exit::status_reason`).
    reason: &'static str,
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
            dns: config
                .dns
                .map(|dns| Arc::new(dns::Resolver::new(dns.defaults))),
            config,
            store,
            catalog,
            devices,
            runner,
            runtime: Mutex::new(Runtime::default()),
            published: std::sync::Mutex::new(Published::default()),
            events: None,
            metrics: None,
            last_pass: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Samples every location into `metrics` on each pass.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Records location and route changes in the event history.
    pub fn with_events(mut self, events: Arc<EventLog>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn dry_run(&self) -> bool {
        self.config.dry_run
    }

    pub fn unassigned_policy(&self) -> UnassignedPolicy {
        self.config.unassigned
    }

    /// The per-client DNS plan, when the DNS forwarder is enabled.
    pub fn dns(&self) -> Option<&Arc<dns::Resolver>> {
        self.dns.as_ref()
    }

    pub async fn install_baseline(&self) -> Result<()> {
        let compiled = policy::compile(policy::Input {
            wan_interface: &self.config.wan_interface,
            tailscale_interface: &self.config.tailscale_interface,
            exits: &[],
            devices: &[],
            assignments: &[],
            unassigned: UnassignedPolicy::Block,
            dns_port: self.config.dns.map(|dns| dns.port),
        })?;
        self.apply_ruleset(&compiled.ruleset).await?;
        self.apply_usage_table().await
    }

    /// Installs (or re-asserts) the observe-only table that records which
    /// devices send Internet traffic through the gateway. Keeps its data.
    async fn apply_usage_table(&self) -> Result<()> {
        fs::create_dir_all(&self.config.runtime_directory)?;
        let path = self.config.runtime_directory.join("usage.nft");
        fs::write(&path, usage::ruleset(&self.config.tailscale_interface))
            .context("write the usage table")?;
        if self.config.dry_run {
            return Ok(());
        }
        let path = path.to_string_lossy().into_owned();
        self.runner.run("nft", ["-f", &path]).await?;
        Ok(())
    }

    /// Seconds since each tailnet address last sent Internet traffic through
    /// the gateway (within `usage::WINDOW`); empty if unavailable.
    /// Every tailnet device with its VPN route (if any) and whether it sends
    /// Internet traffic through the gateway, for the exit node alert.
    pub async fn device_usage(&self) -> Result<Vec<DeviceUse>> {
        let desired = self.store.load()?;
        let devices = self.devices.devices().await?;
        let usage = self.exit_usage().await;
        let exits: HashMap<&str, &str> = desired
            .exits
            .iter()
            .map(|exit| (exit.id.as_str(), exit.display_name.as_str()))
            .collect();
        let routes: HashMap<&str, &str> = desired
            .assignments
            .iter()
            .filter(|assignment| !is_builtin_route(&assignment.exit_id))
            .filter_map(|assignment| {
                exits
                    .get(assignment.exit_id.as_str())
                    .map(|name| (assignment.node_id.as_str(), *name))
            })
            .collect();
        Ok(devices
            .into_iter()
            .map(|device| DeviceUse {
                route: routes
                    .get(device.node_id.as_str())
                    .map(|name| (*name).to_owned()),
                using: device.addresses.iter().any(
                    |address| matches!(address, IpAddr::V4(address) if usage.contains_key(address)),
                ),
                name: if device.display_name.is_empty() {
                    device.node_id.clone()
                } else {
                    device.display_name
                },
                node_id: device.node_id,
                online: device.online,
            })
            .collect())
    }

    pub async fn exit_usage(&self) -> HashMap<Ipv4Addr, u64> {
        if self.config.dry_run {
            return HashMap::new();
        }
        match self
            .runner
            .run(
                "nft",
                ["-j", "list", "set", "inet", usage::TABLE, usage::SET],
            )
            .await
        {
            Ok(output) => usage::parse(&output).unwrap_or_else(|error| {
                warn!(%error, "cannot read exit node usage");
                HashMap::new()
            }),
            Err(error) => {
                warn!(%error, "cannot read exit node usage");
                HashMap::new()
            }
        }
    }

    fn published(&self) -> std::sync::MutexGuard<'_, Published> {
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the last reconcile saw Tailscale running with an authoritative peer list.
    pub async fn tailscale_running(&self) -> bool {
        self.published().tailscale_running
    }

    /// Revision of the desired state that is currently enforced in the kernel.
    pub async fn applied_revision(&self) -> Option<u64> {
        self.published().applied_revision
    }

    pub async fn snapshot(&self) -> (Vec<Exit>, String) {
        let published = self.published();
        (published.exits.clone(), published.last_error.clone())
    }

    /// Time since the last reconcile pass finished (or since start).
    pub fn since_last_pass(&self) -> Duration {
        self.last_pass
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed()
    }

    /// Whether the DNS forwarder answers devices; `None` when it is off.
    pub fn dns_ready(&self) -> Option<bool> {
        self.dns.as_ref().map(|resolver| resolver.ready())
    }

    /// What keeps the gateway from routing; empty when it is ready.
    pub async fn not_ready(&self) -> Vec<&'static str> {
        let published = {
            let published = self.published();
            (published.tailscale_running, published.applied_revision)
        };
        let mut reasons = Vec::new();
        if !published.0 {
            reasons.push("tailscale.stopped");
        }
        if published.1.is_none() {
            reasons.push("rules.not_applied");
        }
        if self.dns_ready() == Some(false) {
            reasons.push("dns.not_ready");
        }
        reasons
    }

    pub async fn reconcile(&self) -> Result<()> {
        let started = Instant::now();
        let result = self.reconcile_inner().await;
        if let Some(metrics) = &self.metrics {
            metrics.record_pass(started.elapsed(), result.is_err());
        }
        *self
            .last_pass
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.published().last_error = error.to_string();
                Err(error)
            }
        }
    }

    async fn reconcile_inner(&self) -> Result<()> {
        // Everything is read under the lock: a reconcile that read its inputs before
        // waiting could otherwise apply an older revision after a newer one.
        let mut runtime = self.runtime.lock().await;
        let mut desired = self.store.load()?;
        let revision = desired.revision;
        if let Some(applied) = runtime.applied_revision
            && revision < applied
        {
            bail!("desired state revision {revision} is older than applied revision {applied}");
        }
        let (devices, tailscale_running) = match self.devices.snapshot().await {
            Ok(snapshot) => (snapshot.devices, snapshot.running),
            Err(_) if self.config.dry_run => (Vec::new(), true),
            Err(error) => return Err(error),
        };
        desired.exits.sort_by(|left, right| left.id.cmp(&right.id));
        let desired_ids: HashSet<_> = desired.exits.iter().map(|exit| exit.id.clone()).collect();

        self.remove_stale_tunnels(&mut runtime, &desired_ids).await;
        let mut runtime_exits = Vec::with_capacity(desired.exits.len());
        let mut verdicts = Vec::with_capacity(desired.exits.len());
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
                    Ok(resolver) => {
                        wanted.resolver = resolver;
                        self.check_tunnel(&mut runtime, &wanted).await
                    }
                },
            };
            runtime_exits.push(wanted);
            verdicts.push(verdict);
        }
        self.probe_tunnels(&mut runtime, &runtime_exits, &mut verdicts)
            .await;
        for (wanted, verdict) in runtime_exits.iter_mut().zip(verdicts) {
            if verdict.rebuild {
                // Dropping the fingerprint makes the next reconcile recreate the tunnel.
                runtime.tunnels.remove(&wanted.id);
            }
            if verdict.status != ExitStatus::Healthy {
                debug!(exit = %wanted.id, status = ?verdict.status, detail = %verdict.detail, "exit not healthy");
            }
            wanted.status = verdict.status;
            wanted.status_detail = verdict.detail;
            wanted.status_reason = verdict.reason.to_owned();
            wanted.public_ip = runtime
                .probes
                .get(&wanted.id)
                .and_then(|probe| probe.public_ip)
                .map(|address| address.to_string())
                .unwrap_or_default();
        }
        if let Some(metrics) = &self.metrics {
            metrics.record_exits(
                self.sample_exits(&runtime, &runtime_exits).await,
                sessions_now(),
            );
        }
        if let Some(events) = &self.events {
            for exit in &runtime_exits {
                let (event, remember) =
                    history::location_event(runtime.recorded.get(&exit.id), exit);
                if let Some(event) = event {
                    events.record(event);
                }
                if remember {
                    runtime.recorded.insert(
                        exit.id.clone(),
                        history::Recorded {
                            status: exit.status,
                            public_ip: exit.public_ip.clone(),
                        },
                    );
                }
            }
            runtime.recorded.retain(|id, _| desired_ids.contains(id));
        }
        let compiled = policy::compile(policy::Input {
            wan_interface: &self.config.wan_interface,
            tailscale_interface: &self.config.tailscale_interface,
            exits: &runtime_exits,
            devices: &devices,
            assignments: &desired.assignments,
            unassigned: self.config.unassigned,
            dns_port: self.config.dns.map(|dns| dns.port),
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
        if let Err(error) = self.apply_usage_table().await {
            // Observation only: never let it fail routing.
            warn!(%error, "cannot install the exit node usage table");
        }
        // The first rules after a start are not changes.
        if let Some(events) = &self.events
            && runtime.applied_revision.is_some()
        {
            for event in history::route_events(
                &runtime.applied_routes,
                &compiled.routes,
                &devices,
                &runtime_exits,
                &desired.assignments,
            ) {
                events.record(event);
            }
        }
        self.reset_moved_connections(&runtime.applied_routes, &compiled.routes)
            .await;
        runtime.applied_routes = compiled.routes;
        runtime.applied_revision = Some(revision);
        if let Some(resolver) = &self.dns {
            // Without an authoritative peer list every client would look unknown
            // and get the default server over the WAN; fail closed instead.
            if tailscale_running {
                resolver.replace(dns::plan(dns::PlanInput {
                    devices: &devices,
                    assignments: &desired.assignments,
                    exits: &runtime_exits,
                    settings: &desired.dns,
                    defaults: resolver.defaults(),
                }));
            } else {
                resolver.clear();
            }
        }
        *self.published() = Published {
            exits: runtime_exits,
            last_error: String::new(),
            applied_revision: Some(revision),
            tailscale_running,
        };
        Ok(())
    }

    async fn ensure_tunnel(
        &self,
        runtime: &mut Runtime,
        exit: &Exit,
        config_path: &str,
    ) -> Result<Option<Ipv4Addr>> {
        let configuration = wireguard::parse_file(config_path)?;
        let resolver = configuration.dns.first().copied();
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
                return Ok(resolver);
            }
            warn!(exit = %exit.id, interface = %exit.interface, "tunnel interface missing or down; recreating");
        }
        if self.config.dry_run {
            runtime.tunnels.insert(exit.id.clone(), fingerprint);
            runtime.created.insert(exit.id.clone(), Instant::now());
            return Ok(resolver);
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
        // When the tunnel route disappears (interface down or deleted), lookups in
        // this table must fail instead of falling through to the main table and
        // leaving over the WAN. This also covers the gateway's own DNS queries,
        // which the forward chain never sees.
        commands.push(unreachable_fallback_route(exit.table));
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
        Ok(resolver)
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
                reason: "ok",
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
                reason: "tunnel.unreadable",
            },
            Ok(latest) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age = latest.map(|seconds| Duration::from_secs(now.saturating_sub(seconds)));
                let verdict = classify(
                    age,
                    runtime
                        .created
                        .get(&exit.id)
                        .map_or(Duration::MAX, Instant::elapsed),
                );
                if verdict.reason == "handshake.never" {
                    self.explain_missing_handshake(exit, verdict).await
                } else {
                    verdict
                }
            }
        }
    }

    /// A tunnel that never completed a handshake: if nothing at all came back
    /// from the server, say so, because that points away from this gateway.
    async fn explain_missing_handshake(&self, exit: &Exit, verdict: Verdict) -> Verdict {
        let received = self
            .runner
            .run("wg", ["show", &exit.interface, "transfer"])
            .await
            .ok()
            .and_then(|output| parse_received(&String::from_utf8_lossy(&output)));
        let endpoint = self
            .runner
            .run("wg", ["show", &exit.interface, "endpoints"])
            .await
            .ok()
            .and_then(|output| {
                String::from_utf8_lossy(&output)
                    .split_whitespace()
                    .nth(1)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "its endpoint".into());
        match received {
            Some(0) => Verdict {
                detail: format!(
                    "no reply from the server at {endpoint} since the tunnel was created: it may be unreachable, or not accepting this key; recreating"
                ),
                reason: "handshake.no_reply",
                ..verdict
            },
            _ => verdict,
        }
    }

    /// Handshake age, traffic totals, and probe time for each location.
    async fn sample_exits(&self, runtime: &Runtime, exits: &[Exit]) -> Vec<ExitSample> {
        let read = |arguments: [&'static str; 3]| async move {
            if self.config.dry_run {
                return HashMap::new();
            }
            self.runner
                .run("wg", arguments)
                .await
                .map(|output| per_interface(&String::from_utf8_lossy(&output)))
                .unwrap_or_default()
        };
        let handshakes = read(["show", "all", "latest-handshakes"]).await;
        let transfer = read(["show", "all", "transfer"]).await;
        let now = sessions_now();
        exits
            .iter()
            .map(|exit| {
                let totals = transfer.get(&exit.interface);
                ExitSample {
                    name: exit.display_name.clone(),
                    status: exit.status,
                    handshake_age: handshakes
                        .get(&exit.interface)
                        .and_then(|values| values.first().copied())
                        .filter(|seconds| *seconds > 0)
                        .map(|seconds| Duration::from_secs(now.saturating_sub(seconds))),
                    received_bytes: totals
                        .and_then(|values| values.first().copied())
                        .unwrap_or(0),
                    sent_bytes: totals
                        .and_then(|values| values.get(1).copied())
                        .unwrap_or(0),
                    probe: runtime
                        .probes
                        .get(&exit.id)
                        .and_then(|probe| probe.round_trip),
                }
            })
            .collect()
    }

    /// Send traffic through every tunnel whose handshake looks fine, concurrently.
    async fn probe_tunnels(&self, runtime: &mut Runtime, exits: &[Exit], verdicts: &mut [Verdict]) {
        if self.config.dry_run {
            return;
        }
        let mut probes = tokio::task::JoinSet::new();
        for (index, (exit, verdict)) in exits.iter().zip(verdicts.iter()).enumerate() {
            if policy::routable(&verdict.status) {
                let (mark, resolver) = (exit.mark, exit.resolver);
                probes.spawn(async move {
                    let started = Instant::now();
                    let outcome = probe::run(mark, resolver).await;
                    (index, outcome, started.elapsed())
                });
            }
        }
        while let Some(result) = probes.join_next().await {
            let Ok((index, outcome, round_trip)) = result else {
                continue;
            };
            let state = runtime.probes.entry(exits[index].id.clone()).or_default();
            state.round_trip = outcome.egress.is_ok().then_some(round_trip);
            let verdict = std::mem::replace(&mut verdicts[index], failed(String::new()));
            verdicts[index] = assess_probe(verdict, state, outcome);
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
            debug!(address = %source, route = current.get(&address).map_or("removed", String::as_str), "route changed; reset tracked connections");
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
            runtime.probes.remove(&exit_id);
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
        reason: "tunnel.setup",
    }
}

/// The numbers after the peer key on each line of `wg show all <field>`,
/// by interface (one peer per interface here).
fn per_interface(output: &str) -> HashMap<String, Vec<u64>> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let interface = fields.next()?.to_owned();
            let _peer = fields.next()?;
            let values = fields.filter_map(|field| field.parse().ok()).collect();
            Some((interface, values))
        })
        .collect()
}

fn sessions_now() -> u64 {
    crate::sessions::now()
}

/// Bytes received, from `wg show <interface> transfer` (one peer).
fn parse_received(output: &str) -> Option<u64> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .reduce(|total, bytes| total + bytes)
}

fn assess_probe(verdict: Verdict, state: &mut ProbeState, outcome: probe::Outcome) -> Verdict {
    match outcome.egress {
        Ok(address) => {
            state.egress_failures = 0;
            state.public_ip = Some(address);
        }
        Err(error) => {
            state.egress_failures += 1;
            let failures = state.egress_failures;
            if failures < PROBE_FAILURE_LIMIT {
                return degrade(
                    verdict,
                    "probe.egress",
                    format!("traffic probe failed: {error}"),
                );
            }
            return Verdict {
                status: ExitStatus::Failed,
                detail: format!(
                    "handshakes succeed but no traffic passes ({failures} probes failed: {error}); the VPN key, its certificate, or the account may no longer be valid"
                ),
                rebuild: verdict.rebuild
                    || (failures - PROBE_FAILURE_LIMIT) % PROBE_REBUILD_EVERY == 0,
                reason: "probe.egress",
            };
        }
    }
    match outcome.resolver {
        Ok(()) => {
            state.resolver_failures = 0;
            verdict
        }
        Err(error) => {
            state.resolver_failures += 1;
            if state.resolver_failures < PROBE_FAILURE_LIMIT {
                return verdict;
            }
            degrade(
                verdict,
                "probe.resolver",
                format!("VPN DNS resolver not answering: {error}"),
            )
        }
    }
}

/// Lower a healthy verdict to degraded, keeping any existing detail and the
/// reason of a verdict that was already worse.
fn degrade(verdict: Verdict, code: &'static str, reason: String) -> Verdict {
    let detail = if verdict.detail.is_empty() {
        reason
    } else {
        format!("{}; {reason}", verdict.detail)
    };
    Verdict {
        reason: if verdict.status == ExitStatus::Healthy {
            code
        } else {
            verdict.reason
        },
        status: match verdict.status {
            ExitStatus::Healthy => ExitStatus::Degraded,
            status => status,
        },
        detail,
        rebuild: verdict.rebuild,
    }
}

fn classify(handshake_age: Option<Duration>, since_created: Duration) -> Verdict {
    let verdict = |status, reason, detail: String, rebuild| Verdict {
        status,
        detail,
        rebuild,
        reason,
    };
    match handshake_age {
        Some(age) if age <= HEALTHY_HANDSHAKE_AGE => {
            verdict(ExitStatus::Healthy, "ok", String::new(), false)
        }
        Some(age) if age <= STALE_HANDSHAKE_AGE => verdict(
            ExitStatus::Degraded,
            "handshake.stale",
            format!("last handshake {}s ago", age.as_secs()),
            false,
        ),
        Some(age) => verdict(
            ExitStatus::Failed,
            "handshake.lost",
            format!("no handshake for {}s; recreating", age.as_secs()),
            true,
        ),
        None if since_created <= FIRST_HANDSHAKE_GRACE => verdict(
            ExitStatus::Pending,
            "handshake.waiting",
            "waiting for first handshake".into(),
            false,
        ),
        None => verdict(
            ExitStatus::Failed,
            "handshake.never",
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

fn unreachable_fallback_route(table: u32) -> Vec<String> {
    [
        "route",
        "replace",
        "unreachable",
        "default",
        "metric",
        "4294967295",
        "table",
    ]
    .into_iter()
    .map(String::from)
    .chain([table.to_string()])
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

    fn dry_run_reconciler(directory: &std::path::Path) -> (Arc<Store>, Arc<Reconciler>) {
        let store = Arc::new(Store::new(directory.join("state/desired.json")));
        let reconciler = Arc::new(Reconciler::new(
            Config {
                wan_interface: "eth0".into(),
                tailscale_interface: "tailscale0".into(),
                runtime_directory: directory.join("run"),
                dry_run: true,
                unassigned: UnassignedPolicy::Block,
                dns: None,
            },
            store.clone(),
            Arc::new(StaticCatalog::new(
                directory.join("catalog.json"),
                directory.join("secrets"),
            )),
            Arc::new(Provider::new(Runner::new(true))),
            Runner::new(true),
        ));
        (store, reconciler)
    }

    #[tokio::test]
    async fn concurrent_reconciles_end_on_the_latest_revision() {
        let directory = tempfile::tempdir().unwrap();
        let (store, reconciler) = dry_run_reconciler(directory.path());
        for revision in 0..20 {
            store.update(revision, |_| Ok(())).unwrap();
            let first = tokio::spawn({
                let reconciler = reconciler.clone();
                async move { reconciler.reconcile().await }
            });
            let second = tokio::spawn({
                let reconciler = reconciler.clone();
                async move { reconciler.reconcile().await }
            });
            first.await.unwrap().unwrap();
            second.await.unwrap().unwrap();
            assert_eq!(reconciler.applied_revision().await, Some(revision + 1));
        }
    }

    #[tokio::test]
    async fn refuses_to_apply_an_older_revision() {
        let directory = tempfile::tempdir().unwrap();
        let (store, reconciler) = dry_run_reconciler(directory.path());
        store.update(0, |_| Ok(())).unwrap();
        reconciler.runtime.lock().await.applied_revision = Some(5);
        let error = reconciler.reconcile().await.unwrap_err();
        assert!(error.to_string().contains("older than applied revision 5"));
        assert_eq!(reconciler.runtime.lock().await.applied_revision, Some(5));
        assert_eq!(reconciler.snapshot().await.1, error.to_string());
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
        assert_eq!(
            [
                classify(Some(secs(30)), secs(600)).reason,
                degraded.reason,
                stale.reason,
                classify(None, secs(10)).reason,
                never.reason,
            ],
            [
                "ok",
                "handshake.stale",
                "handshake.lost",
                "handshake.waiting",
                "handshake.never"
            ]
        );
    }

    #[test]
    fn reads_values_per_interface() {
        let parsed = per_interface("proton0\tpeerA=\t1790713273\nproton2\tpeerB=\t0\n");
        assert_eq!(parsed["proton0"], [1_790_713_273]);
        assert_eq!(parsed["proton2"], [0]);
        let transfer = per_interface("proton0\tpeerA=\t327119848\t2310\n");
        assert_eq!(transfer["proton0"], [327_119_848, 2310]);
    }

    #[test]
    fn reads_received_bytes_and_keeps_the_worse_reason() {
        assert_eq!(parse_received("peerkey=\t0\t2310\n"), Some(0));
        assert_eq!(
            parse_received("peerkey=\t225202368\t2310\n"),
            Some(225_202_368)
        );
        assert_eq!(parse_received(""), None);
        let healthy = classify(Some(Duration::from_secs(10)), Duration::from_secs(600));
        assert_eq!(
            degrade(healthy, "probe.egress", "x".into()).reason,
            "probe.egress"
        );
        let stale = classify(Some(Duration::from_secs(240)), Duration::from_secs(600));
        assert_eq!(
            degrade(stale, "probe.resolver", "x".into()).reason,
            "handshake.stale"
        );
    }

    fn healthy() -> Verdict {
        classify(Some(Duration::from_secs(10)), Duration::from_secs(600))
    }

    fn outcome(egress: Result<Ipv4Addr, &str>, resolver: Result<(), &str>) -> probe::Outcome {
        probe::Outcome {
            egress: egress.map_err(String::from),
            resolver: resolver.map_err(String::from),
        }
    }

    #[test]
    fn a_tunnel_that_passes_no_traffic_fails_despite_fresh_handshakes() {
        let address = Ipv4Addr::new(146, 70, 86, 115);
        let mut state = ProbeState::default();
        let verdict = assess_probe(healthy(), &mut state, outcome(Ok(address), Ok(())));
        assert_eq!(verdict, healthy());
        assert_eq!(state.public_ip, Some(address));

        let first = assess_probe(
            healthy(),
            &mut state,
            outcome(Err("timeout"), Err("timeout")),
        );
        assert_eq!(first.status, ExitStatus::Degraded);
        assert!(!first.rebuild);
        let second = assess_probe(
            healthy(),
            &mut state,
            outcome(Err("timeout"), Err("timeout")),
        );
        assert_eq!(second.status, ExitStatus::Failed);
        assert!(second.rebuild);
        assert!(second.detail.contains("no traffic passes"));
        // Rebuilds are spaced out while the failure persists.
        let rebuilds: Vec<bool> = (0..PROBE_REBUILD_EVERY)
            .map(|_| assess_probe(healthy(), &mut state, outcome(Err("timeout"), Ok(()))).rebuild)
            .collect();
        assert_eq!(rebuilds.iter().filter(|rebuild| **rebuild).count(), 1);
        assert!(rebuilds[rebuilds.len() - 1]);
        // The last known address stays visible; one success recovers.
        assert_eq!(state.public_ip, Some(address));
        assert_eq!(
            assess_probe(healthy(), &mut state, outcome(Ok(address), Ok(()))).status,
            ExitStatus::Healthy
        );
        assert_eq!(state.egress_failures, 0);
    }

    #[test]
    fn a_silent_tunnel_resolver_degrades_the_exit() {
        let address = Ipv4Addr::new(146, 70, 86, 115);
        let mut state = ProbeState::default();
        let once = assess_probe(healthy(), &mut state, outcome(Ok(address), Err("timeout")));
        assert_eq!(once.status, ExitStatus::Healthy);
        let twice = assess_probe(healthy(), &mut state, outcome(Ok(address), Err("timeout")));
        assert_eq!(twice.status, ExitStatus::Degraded);
        assert!(twice.detail.contains("VPN DNS resolver"));
        assert!(!twice.rebuild);
        let degraded = classify(Some(Duration::from_secs(240)), Duration::from_secs(600));
        let combined = assess_probe(degraded, &mut state, outcome(Ok(address), Err("timeout")));
        assert!(combined.detail.starts_with("last handshake"));
        assert!(combined.detail.contains("; VPN DNS resolver"));
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
    fn tunnel_tables_end_in_an_unreachable_route() {
        assert_eq!(
            unreachable_fallback_route(10_003).join(" "),
            "route replace unreachable default metric 4294967295 table 10003"
        );
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
