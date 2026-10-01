use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tailway::alert::{self, Alerts};
use tailway::catalog::StaticCatalog;
use tailway::control::Api;
use tailway::custom::CustomExits;
use tailway::dns::{self, DnsServer};
use tailway::domain::{ExitStatus, UnassignedPolicy};
use tailway::events::{Category, Event, EventLog, Severity};
use tailway::exit_watch::{self, ExitNodeWatch};
use tailway::health::{Alert, Health, Report, Status};
use tailway::host;
use tailway::metrics::{self, Metrics};
use tailway::notify::{self, Notifier, SettingsStore};
use tailway::platform::Runner;
use tailway::proton::AccountLimits;
use tailway::reconcile::{Config, DnsConfig, Reconciler};
use tailway::state::Store;
use tailway::tailscale::Provider;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().nth(1).as_deref() == Some("--version") {
        println!("tailway {}", tailway::VERSION);
        return Ok(());
    }
    tailway::logging::init();
    let dry_run = environment("DRY_RUN", "false").parse().unwrap_or(false);
    let unassigned: UnassignedPolicy = environment("UNASSIGNED_POLICY", "block").parse()?;
    let dns_config = dns_config()?;
    let runner = Runner::new(dry_run);
    let wan_interface = environment("WAN_INTERFACE", "eth0");
    let state_path = PathBuf::from(environment("STATE_PATH", "/var/lib/tailway/desired.json"));
    let state_directory = state_path
        .parent()
        .map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let store = Arc::new(Store::new(state_path));
    let catalog = Arc::new(
        StaticCatalog::new(
            environment("CATALOG_PATH", "/etc/tailway/catalog.json"),
            environment("SECRETS_DIRECTORY", "/run/secrets/proton"),
        )
        // WireGuard configurations imported in the console, from any provider.
        .with_custom(CustomExits::new(environment(
            "CUSTOM_EXITS_DIRECTORY",
            "/var/lib/tailway/custom-exits",
        ))),
    );
    let events = Arc::new(EventLog::new(environment(
        "EVENTS_DIRECTORY",
        "/var/lib/tailway/events",
    )));
    let (alerts, notifier) = start_alerts(events.clone())?;
    let health = Arc::new(Health::new(Some(alerts.clone())));
    let metrics = Arc::new(Metrics::new(Some(state_directory.join("metrics.json"))));
    let devices = Arc::new(Provider::new(runner.clone()));
    let reconciler = Arc::new(
        Reconciler::new(
            Config {
                wan_interface: wan_interface.clone(),
                tailscale_interface: environment("TAILSCALE_INTERFACE", "tailscale0"),
                runtime_directory: PathBuf::from(environment("RUNTIME_DIRECTORY", "/run/tailway")),
                dry_run,
                unassigned,
                dns: dns_config,
            },
            store.clone(),
            catalog.clone(),
            devices.clone(),
            runner.clone(),
        )
        .with_events(events.clone())
        .with_metrics(metrics.clone()),
    );

    reconciler
        .install_baseline()
        .await
        .context("install fail-closed baseline")?;
    if let (Some(dns_config), Some(resolver)) = (dns_config, reconciler.dns()) {
        let server =
            DnsServer::bind((std::net::Ipv4Addr::UNSPECIFIED, dns_config.port).into()).await?;
        info!(
            port = dns_config.port,
            default_server = %dns_config.defaults.server,
            kill_switch_default = dns_config.defaults.kill_switch,
            "DNS forwarder ready"
        );
        tokio::spawn(server.run(resolver.clone(), dns::is_tailnet));
    }
    let mut tailscaled = if !dry_run && environment("START_TAILSCALED", "true") == "true" {
        enable_udp_gro_forwarding(&runner, &wan_interface).await;
        Some(start_tailscaled().await?)
    } else {
        None
    };
    alerts.info(
        "agent",
        "gateway agent started",
        format!(
            "Gateway agent {} started; routing is being restored.",
            tailway::VERSION
        ),
    );
    let result = reconciler.reconcile().await;
    if let Err(error) = &result {
        error!(%error, "initial reconciliation failed; forwarding remains closed");
    }
    let mut exit_watch = ExitNodeWatch::default();
    observe_health(
        &health,
        &reconciler,
        &mut exit_watch,
        result.is_err(),
        &state_directory,
    )
    .await;

    let interval = parse_interval(&environment("RECONCILE_INTERVAL", "30s"));
    let loop_reconciler = reconciler.clone();
    let loop_health = health.clone();
    let started = std::time::Instant::now();
    let reconcile_task = tokio::spawn(async move {
        loop {
            // Retry quickly while Tailscale is still coming up after a restart, so
            // routing and DNS become available within seconds, not one interval.
            let starting = started.elapsed() < STARTUP_FAST_RETRY_WINDOW
                && !loop_reconciler.tailscale_running().await;
            tokio::time::sleep(if starting { STARTUP_RETRY } else { interval }).await;
            let result = loop_reconciler.reconcile().await;
            if let Err(error) = &result {
                error!(%error, "reconciliation failed; forwarding remains closed");
            }
            observe_health(
                &loop_health,
                &loop_reconciler,
                &mut exit_watch,
                result.is_err(),
                &state_directory,
            )
            .await;
        }
    });

    let socket_path = PathBuf::from(environment("CONTROL_SOCKET", "/run/tailway/control.sock"));
    if let Some(directory) = socket_path.parent() {
        let created = !directory.exists();
        fs::create_dir_all(directory).context("create control socket directory")?;
        if created {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o770))?;
        }
    }
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path).context("listen on control socket")?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .context("set control socket permissions")?;
    info!(socket = %socket_path.display(), dry_run, unassigned = unassigned.as_str(), "gateway agent control API ready");

    let account_limits = Arc::new(AccountLimits::new(environment(
        "PROTON_BROKER_SOCKET",
        "/run/tailway/proton.sock",
    )));
    let account_task = tokio::spawn(watch_account(account_limits.clone(), health.clone()));
    let metrics_task = tokio::spawn(save_metrics_hourly(metrics.clone()));
    let exporter_task = start_exporter(
        runner.clone(),
        metrics.clone(),
        health.clone(),
        alerts.clone(),
        reconciler.clone(),
    );
    let router = Arc::new(
        Api::new(
            store,
            catalog,
            devices,
            reconciler,
            account_limits,
            alerts,
            notifier,
        )
        .with_events(events.clone())
        .with_metrics(metrics.clone())
        // Alive while reconcile passes keep completing, whatever their result.
        .with_health(health.clone(), (interval * 5).max(LIVENESS_MIN)),
    )
    .router();
    let mut gateway_ui = start_gateway_ui()?;
    let server = async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
    };
    tokio::pin!(server);
    let serve_result: Result<()> = tokio::select! {
        result = &mut server => result.context("serve gateway agent API"),
        status = gateway_ui.wait() => match status {
            Ok(status) => Err(anyhow::anyhow!("gateway UI exited unexpectedly: {status}")),
            Err(error) => Err(error).context("wait for gateway UI"),
        },
    };
    reconcile_task.abort();
    account_task.abort();
    metrics_task.abort();
    if let Some(task) = exporter_task {
        task.abort();
    }
    if let Err(error) = metrics.save() {
        warn!(error = %format!("{error:#}"), "cannot save the metrics history");
    }
    let _ = gateway_ui.start_kill();
    let _ = gateway_ui.wait().await;
    if let Some(child) = tailscaled.as_mut() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let _ = fs::remove_file(socket_path);
    events.record(Event::new(
        Severity::Info,
        Category::System,
        "agent.stopped",
        format!("Gateway agent {} stopped", tailway::VERSION),
    ));
    serve_result
}

async fn save_metrics_hourly(metrics: Arc<Metrics>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        if let Err(error) = metrics.save() {
            warn!(error = %format!("{error:#}"), "cannot save the metrics history");
        }
    }
}

/// Serves Prometheus metrics on the gateway's tailnet address only
/// (`METRICS_PORT`, default 9091; `METRICS=false` turns it off). Waits for
/// Tailscale to have an address.
fn start_exporter(
    runner: Runner,
    metrics: Arc<Metrics>,
    health: Arc<Health>,
    alerts: Arc<Alerts>,
    reconciler: Arc<Reconciler>,
) -> Option<tokio::task::JoinHandle<()>> {
    if environment("METRICS", "true") != "true" || runner.dry_run() {
        return None;
    }
    let port: u16 = match environment("METRICS_PORT", "9091").parse() {
        Ok(port) => port,
        Err(error) => {
            warn!(%error, "invalid METRICS_PORT; metrics are off");
            return None;
        }
    };
    Some(tokio::spawn(async move {
        let listener = loop {
            let address = runner
                .run("tailscale", ["ip", "-4"])
                .await
                .ok()
                .and_then(|output| {
                    String::from_utf8_lossy(&output)
                        .trim()
                        .parse::<std::net::Ipv4Addr>()
                        .ok()
                });
            if let Some(address) = address {
                match tokio::net::TcpListener::bind((address, port)).await {
                    Ok(listener) => {
                        info!(%address, port, "Prometheus metrics at /metrics, on the tailnet only");
                        break listener;
                    }
                    Err(error) => {
                        warn!(%error, %address, port, "cannot listen for metrics; retrying")
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        };
        let router = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let (metrics, health, alerts, reconciler) = (
                    metrics.clone(),
                    health.clone(),
                    alerts.clone(),
                    reconciler.clone(),
                );
                async move {
                    let checks = health.checks();
                    let text = metrics.prometheus(&metrics::Extra {
                        dns: reconciler.dns().map(|resolver| resolver.counters()),
                        checks: &checks,
                        alerts_active: alerts
                            .active()
                            .iter()
                            .filter(|alert| alert.notified)
                            .count(),
                    });
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; version=0.0.4",
                        )],
                        text,
                    )
                }
            }),
        );
        if let Err(error) = axum::serve(listener, router).await {
            warn!(%error, "metrics server stopped");
        }
    }))
}

fn start_gateway_ui() -> Result<Child> {
    let control_gid = environment("CONTROL_GID", "1000")
        .parse::<u32>()
        .context("parse CONTROL_GID")?;
    let mut command = Command::new("gateway-ui");
    command.uid(65_532).gid(control_gid).kill_on_drop(true);
    command.spawn().context("start gateway UI")
}

/// Tailscale's recommended offload setting for exit nodes: forwarded UDP is
/// coalesced like TCP, which cuts per-packet CPU. Best effort; some drivers
/// lack it, and it resets whenever the interface is recreated.
async fn enable_udp_gro_forwarding(runner: &Runner, interface: &str) {
    let arguments = [
        "-K",
        interface,
        "rx-udp-gro-forwarding",
        "on",
        "rx-gro-list",
        "off",
    ];
    match runner.run("ethtool", arguments).await {
        Ok(_) => info!(interface, "UDP GRO forwarding enabled"),
        Err(error) => warn!(interface, %error, "cannot enable UDP GRO forwarding"),
    }
}

async fn start_tailscaled() -> Result<Child> {
    let state_path = PathBuf::from(environment(
        "TAILSCALE_STATE",
        "/var/lib/tailscale/tailscaled.state",
    ));
    if let Some(directory) = state_path.parent() {
        fs::create_dir_all(directory)?;
    }
    // The listen port must equal the published host port: Tailscale advertises
    // its own port as an endpoint, and a mismatch breaks direct connections.
    let port: u16 = environment("TAILSCALE_PORT", "41641")
        .parse()
        .context("parse TAILSCALE_PORT")?;
    let mut child = Command::new("tailscaled")
        .arg(format!("--state={}", state_path.display()))
        .arg("--socket=/var/run/tailscale/tailscaled.sock")
        .arg("--tun=tailscale0")
        .arg(format!("--port={port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tailscaled")?;
    // tailscaled's output goes through our log, filtered (see `logging`).
    let verbose = environment("TAILSCALE_LOG", "warnings") == "verbose";
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(forward_lines(stdout, verbose));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(forward_lines(stderr, verbose));
    }
    Ok(child)
}

async fn forward_lines(output: impl tokio::io::AsyncRead + Unpin, verbose: bool) {
    let mut lines = BufReader::new(output).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tailway::logging::log_tailscaled(&line, verbose);
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = interrupt => {},
        _ = terminate => {},
    }
}

/// How long a condition must persist before it is notified. Exit failures are
/// already debounced by the health checks, so they are reported at once.
const RECONCILE_ALERT_GRACE: Duration = Duration::from_secs(90);
const TAILSCALE_ALERT_GRACE: Duration = Duration::from_secs(180);
const PROTON_ALERT_GRACE: Duration = Duration::from_secs(600);
const ACCOUNT_POLL_INTERVAL: Duration = Duration::from_secs(300);
/// Certificates last about a week and are renewed with days to spare; one this
/// close to expiry means renewal is failing.
const CERTIFICATE_ALERT_SECONDS: i64 = 24 * 3600;

fn start_alerts(events: Arc<EventLog>) -> Result<(Arc<Alerts>, Arc<Notifier>)> {
    let settings = Arc::new(SettingsStore::open(
        environment("ALERT_SETTINGS_PATH", "/var/lib/tailway/alerts.json"),
        notify::seed_from_environment()?,
    )?);
    let notifier = Arc::new(Notifier::new(
        settings,
        environment("ALERT_SOURCE", "tailway"),
    )?);
    let (sender, queue) = mpsc::channel(alert::QUEUE_LENGTH);
    tokio::spawn(notifier.clone().run(queue));
    let channels = notify::channels(&notifier.settings().get());
    info!(
        ?channels,
        "alert notifications ready; configure channels on the console's Alerts page"
    );
    Ok((
        Arc::new(Alerts::new(Some(sender)).with_events(events)),
        notifier,
    ))
}

async fn observe_health(
    health: &Health,
    reconciler: &Reconciler,
    exit_watch: &mut ExitNodeWatch,
    reconcile_failed: bool,
    state_directory: &std::path::Path,
) {
    let (exits, last_error) = reconciler.snapshot().await;
    let check =
        |id: &str, group, name: &str, status, reason: &str, message: String, alert| Report {
            id: id.into(),
            group,
            name: name.into(),
            status,
            reason: reason.into(),
            message,
            alert,
        };
    health.report(if reconcile_failed {
        check(
            "reconcile",
            "gateway",
            "Routing rules",
            Status::Failed,
            "reconcile.failed",
            format!("Reconciliation is failing: {last_error}"),
            Alert::on_failure(RECONCILE_ALERT_GRACE),
        )
    } else {
        check(
            "reconcile",
            "gateway",
            "Routing rules",
            Status::Ok,
            "ok",
            "applied".into(),
            Alert::on_failure(RECONCILE_ALERT_GRACE),
        )
    });
    let running = reconciler.tailscale_running().await;
    health.report(check(
        "tailscale",
        "gateway",
        "Tailscale",
        if running { Status::Ok } else { Status::Failed },
        if running { "ok" } else { "tailscale.stopped" },
        if running {
            "running".into()
        } else {
            "Tailscale is not running on the gateway; exit routing and DNS are unavailable.".into()
        },
        Alert::on_failure(TAILSCALE_ALERT_GRACE),
    ));
    if let Some(ready) = reconciler.dns_ready() {
        health.report(check(
            "dns",
            "gateway",
            "DNS forwarder",
            if ready { Status::Ok } else { Status::Failed },
            if ready { "ok" } else { "dns.not_ready" },
            if ready {
                "answering for every device".into()
            } else {
                "answering SERVFAIL until Tailscale's device list is available".into()
            },
            None,
        ));
    }

    let mut locations = Vec::with_capacity(exits.len());
    for exit in &exits {
        let id = format!("exit:{}", exit.display_name);
        let (status, message) = match exit.status {
            ExitStatus::Healthy => (
                Status::Ok,
                if exit.public_ip.is_empty() {
                    "connected".to_owned()
                } else {
                    format!("connected; public IP {}", exit.public_ip)
                },
            ),
            ExitStatus::Degraded => (Status::Warning, exit.status_detail.clone()),
            ExitStatus::Pending => (Status::Unknown, exit.status_detail.clone()),
            // The check's name, and the alert's title, already name the location.
            ExitStatus::Failed => (
                Status::Failed,
                format!("Down; its devices are blocked: {}", exit.status_detail),
            ),
        };
        let reason = if exit.status_reason.is_empty() {
            "ok"
        } else {
            &exit.status_reason
        };
        health.report(check(
            &id,
            "locations",
            &exit.display_name,
            status,
            reason,
            message,
            Alert::on_failure(Duration::ZERO),
        ));
        locations.push(id);
    }
    health.retain("locations", &locations);

    // VPN-routed devices that stop using the gateway as their exit node.
    match reconciler.device_usage().await {
        Ok(devices) => {
            let routed: Vec<String> = devices
                .iter()
                .filter(|device| device.route.is_some())
                .map(exit_watch::key)
                .collect();
            for (key, problem) in exit_watch.evaluate(&devices) {
                if !routed.contains(&key) {
                    continue;
                }
                let name = key.trim_start_matches(exit_watch::KEY_PREFIX).to_owned();
                health.report(match problem {
                    Some(problem) => check(
                        &key,
                        "devices",
                        &name,
                        Status::Warning,
                        "exit_node.stopped",
                        problem,
                        Alert::on_warning(exit_watch::GRACE),
                    ),
                    None => check(
                        &key,
                        "devices",
                        &name,
                        Status::Ok,
                        "ok",
                        "uses the gateway as its exit node".into(),
                        Alert::on_warning(exit_watch::GRACE),
                    ),
                });
            }
            health.retain("devices", &routed);
        }
        Err(error) => warn!(%error, "cannot check which devices use the exit node"),
    }

    health.report(host::disk(state_directory));
    health.report(host::clock());
    health.report(host::conntrack(
        std::path::Path::new(host::CONNTRACK_COUNT),
        std::path::Path::new(host::CONNTRACK_MAX),
    ));
}

async fn watch_account(account_limits: Arc<AccountLimits>, health: Arc<Health>) {
    loop {
        let (session, certificate) = match account_limits.account().await {
            Err(error) => (
                Some(format!(
                    "The Proton account broker is unreachable: {error:#}"
                )),
                None,
            ),
            Ok(account) if !account.authenticated() => (
                Some(format!(
                    "The Proton session is {}; certificates cannot be renewed. Sign in again in the console.",
                    account.state
                )),
                None,
            ),
            Ok(account) => (
                None,
                certificate_problem(
                    account.certificate_valid_seconds,
                    account.background_refresh,
                ),
            ),
        };
        if let Some(problem) = &session {
            warn!(%problem, "Proton account check failed");
        }
        let report = |id: &str, name: &str, problem: Option<String>, reason: &str, alert| Report {
            id: id.into(),
            group: "proton",
            name: name.into(),
            status: if problem.is_some() {
                Status::Failed
            } else {
                Status::Ok
            },
            reason: if problem.is_some() {
                reason.into()
            } else {
                "ok".into()
            },
            message: problem.unwrap_or_else(|| "OK".into()),
            alert,
        };
        health.report(report(
            "proton-session",
            "Proton session",
            session,
            "proton.signed_out",
            Alert::on_failure(PROTON_ALERT_GRACE),
        ));
        health.report(report(
            "proton-certificate",
            "Proton certificate",
            certificate,
            "proton.certificate",
            Alert::on_failure(Duration::ZERO),
        ));
        tokio::time::sleep(ACCOUNT_POLL_INTERVAL).await;
    }
}

fn certificate_problem(valid_seconds: Option<i64>, background_refresh: bool) -> Option<String> {
    if !background_refresh {
        return Some(
            "Proton certificate renewal is not running; tunnels stop passing traffic when the certificate expires."
                .into(),
        );
    }
    match valid_seconds {
        Some(seconds) if seconds < CERTIFICATE_ALERT_SECONDS => Some(format!(
            "The Proton certificate expires in {}h and has not been renewed.",
            seconds.max(0) / 3600
        )),
        _ => None,
    }
}

const STARTUP_RETRY: Duration = Duration::from_secs(2);
const LIVENESS_MIN: Duration = Duration::from_secs(150);
const STARTUP_FAST_RETRY_WINDOW: Duration = Duration::from_secs(120);

fn dns_config() -> Result<Option<DnsConfig>> {
    if !environment("DNS_FORWARDER", "true")
        .parse::<bool>()
        .context("parse DNS_FORWARDER")?
    {
        return Ok(None);
    }
    Ok(Some(DnsConfig {
        defaults: dns::Defaults {
            server: environment("DNS_DEFAULT_SERVER", "9.9.9.9")
                .parse()
                .context("parse DNS_DEFAULT_SERVER as an IPv4 address")?,
            kill_switch: environment("DNS_KILL_SWITCH_DEFAULT", "true")
                .parse()
                .context("parse DNS_KILL_SWITCH_DEFAULT")?,
        },
        port: environment("DNS_LISTEN_PORT", "5353")
            .parse()
            .context("parse DNS_LISTEN_PORT")?,
    }))
}

fn parse_interval(value: &str) -> Duration {
    let parsed = humantime::parse_duration(value)
        .ok()
        .filter(|duration| *duration >= Duration::from_secs(1));
    parsed.unwrap_or(Duration::from_secs(30))
}

fn environment(name: &str, fallback: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.into())
}
