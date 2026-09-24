use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tailscale_exit_policy_router::catalog::StaticCatalog;
use tailscale_exit_policy_router::control::Api;
use tailscale_exit_policy_router::dns::{self, DnsServer};
use tailscale_exit_policy_router::domain::UnassignedPolicy;
use tailscale_exit_policy_router::platform::Runner;
use tailscale_exit_policy_router::proton::AccountLimits;
use tailscale_exit_policy_router::reconcile::{Config, DnsConfig, Reconciler};
use tailscale_exit_policy_router::state::Store;
use tailscale_exit_policy_router::tailscale::Provider;
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tracing::{error, info};

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
    if let Err(error) = reconciler.reconcile().await {
        error!(%error, "initial reconciliation failed; forwarding remains closed");
    }

    let interval = parse_interval(&environment("RECONCILE_INTERVAL", "30s"));
    let loop_reconciler = reconciler.clone();
    let reconcile_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(error) = loop_reconciler.reconcile().await {
                error!(%error, "reconciliation failed; forwarding remains closed");
            }
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
    let router = Api::new(store, catalog, devices, reconciler, account_limits).router();
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
    Command::new("tailscaled")
        .arg(format!("--state={}", state_path.display()))
        .arg("--socket=/var/run/tailscale/tailscaled.sock")
        .arg("--tun=tailscale0")
        .arg("--port=41641")
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
