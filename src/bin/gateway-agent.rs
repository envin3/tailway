use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tailscale_exit_policy_router::alert::{self, Alerts};
use tailscale_exit_policy_router::catalog::StaticCatalog;
use tailscale_exit_policy_router::control::Api;
use tailscale_exit_policy_router::dns::{self, DnsServer};
use tailscale_exit_policy_router::domain::{ExitStatus, UnassignedPolicy};
use tailscale_exit_policy_router::notify::{self, Notifier, SettingsStore};
use tailscale_exit_policy_router::platform::Runner;
use tailscale_exit_policy_router::proton::AccountLimits;
use tailscale_exit_policy_router::reconcile::{Config, DnsConfig, Reconciler};
use tailscale_exit_policy_router::state::Store;
use tailscale_exit_policy_router::tailscale::Provider;
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let dry_run = environment("DRY_RUN", "false").parse().unwrap_or(false);
    let unassigned: UnassignedPolicy = environment("UNASSIGNED_POLICY", "block").parse()?;
    let dns_config = dns_config()?;
    let runner = Runner::new(dry_run);
    let store = Arc::new(Store::new(environment(
        "STATE_PATH",
        "/var/lib/tailscale-exit-policy-router/desired.json",
    )));
    let catalog = Arc::new(StaticCatalog::new(
        environment(
            "CATALOG_PATH",
            "/etc/tailscale-exit-policy-router/catalog.json",
        ),
        environment("SECRETS_DIRECTORY", "/run/secrets/proton"),
    ));
    let (alerts, notifier) = start_alerts()?;
    let devices = Arc::new(Provider::new(runner.clone()));
    let reconciler = Arc::new(Reconciler::new(
        Config {
            wan_interface: environment("WAN_INTERFACE", "eth0"),
            tailscale_interface: environment("TAILSCALE_INTERFACE", "tailscale0"),
            runtime_directory: PathBuf::from(environment(
                "RUNTIME_DIRECTORY",
                "/run/tailscale-exit-policy-router",
            )),
            dry_run,
            unassigned,
            dns: dns_config,
        },
        store.clone(),
        catalog.clone(),
        devices.clone(),
        runner,
    ));

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
        Some(start_tailscaled().await?)
    } else {
        None
    };
    alerts.info(
        "agent",
        "gateway agent started",
        format!(
            "Gateway agent {} started; routing is being restored.",
            env!("CARGO_PKG_VERSION")
        ),
    );
    let result = reconciler.reconcile().await;
    if let Err(error) = &result {
        error!(%error, "initial reconciliation failed; forwarding remains closed");
    }
    observe_health(&alerts, &reconciler, result.is_err()).await;

    let interval = parse_interval(&environment("RECONCILE_INTERVAL", "30s"));
    let loop_reconciler = reconciler.clone();
    let loop_alerts = alerts.clone();
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
            observe_health(&loop_alerts, &loop_reconciler, result.is_err()).await;
        }
    });

    let socket_path = PathBuf::from(environment(
        "CONTROL_SOCKET",
        "/run/tailscale-exit-policy-router/control.sock",
    ));
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
        "/run/tailscale-exit-policy-router/proton.sock",
    )));
    let account_task = tokio::spawn(watch_account(account_limits.clone(), alerts.clone()));
    let router = Api::new(
        store,
        catalog,
        devices,
        reconciler,
        account_limits,
        alerts,
        notifier,
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
    let _ = gateway_ui.start_kill();
    let _ = gateway_ui.wait().await;
    if let Some(child) = tailscaled.as_mut() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let _ = fs::remove_file(socket_path);
    serve_result
}

fn start_gateway_ui() -> Result<Child> {
    let control_gid = environment("CONTROL_GID", "1000")
        .parse::<u32>()
        .context("parse CONTROL_GID")?;
    let mut command = Command::new("gateway-ui");
    command.uid(65_532).gid(control_gid).kill_on_drop(true);
    command.spawn().context("start gateway UI")
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
    Command::new("tailscaled")
        .arg(format!("--state={}", state_path.display()))
        .arg("--socket=/var/run/tailscale/tailscaled.sock")
        .arg("--tun=tailscale0")
        .arg(format!("--port={port}"))
        .spawn()
        .context("start tailscaled")
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

fn start_alerts() -> Result<(Arc<Alerts>, Arc<Notifier>)> {
    let settings = Arc::new(SettingsStore::open(
        environment(
            "ALERT_SETTINGS_PATH",
            "/var/lib/tailscale-exit-policy-router/alerts.json",
        ),
        notify::seed_from_environment()?,
    )?);
    let notifier = Arc::new(Notifier::new(
        settings,
        environment("ALERT_SOURCE", "tailscale-exit-policy-router"),
    )?);
    let (sender, queue) = mpsc::channel(alert::QUEUE_LENGTH);
    tokio::spawn(notifier.clone().run(queue));
    let channels = notify::channels(&notifier.settings().get());
    info!(
        ?channels,
        "alert notifications ready; configure channels on the console's Alerts page"
    );
    Ok((Arc::new(Alerts::new(Some(sender))), notifier))
}

async fn observe_health(alerts: &Alerts, reconciler: &Reconciler, reconcile_failed: bool) {
    let (exits, last_error) = reconciler.snapshot().await;
    alerts.observe(
        "reconcile",
        reconcile_failed.then(|| format!("Reconciliation is failing: {last_error}")),
        RECONCILE_ALERT_GRACE,
    );
    alerts.observe(
        "tailscale",
        (!reconciler.tailscale_running().await).then(|| {
            "Tailscale is not running on the gateway; exit routing and DNS are unavailable."
                .to_owned()
        }),
        TAILSCALE_ALERT_GRACE,
    );
    let mut keys = Vec::with_capacity(exits.len());
    for exit in &exits {
        let key = format!("exit:{}", exit.display_name);
        alerts.observe(
            &key,
            (exit.status == ExitStatus::Failed).then(|| {
                format!(
                    "{} ({}) failed; its devices are blocked. {}",
                    exit.display_name, exit.server_id, exit.status_detail
                )
            }),
            Duration::ZERO,
        );
        keys.push(key);
    }
    alerts.retain("exit:", &keys);
}

async fn watch_account(account_limits: Arc<AccountLimits>, alerts: Arc<Alerts>) {
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
        alerts.observe("proton-session", session, PROTON_ALERT_GRACE);
        alerts.observe("proton-certificate", certificate, Duration::ZERO);
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
