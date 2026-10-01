use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::alert::{Alerts, Notification};
use crate::audit::{self, ACTOR_HEADER, CLIENT_HEADER};
use crate::catalog::StaticCatalog;
use crate::dns;
use crate::domain::{
    Assignment, DesiredState, Exit, ExitStatus, NodeDns, SCHEMA_VERSION, Server, ServerSource,
    is_builtin_route,
};
use crate::events::{self, Category, Event, EventLog, Severity};
use crate::health::Health;
use crate::metrics::Metrics;
use crate::notify::{self, Notifier, Settings, Telegram, Webhook};
use crate::proton::AccountLimits;
use crate::reconcile::Reconciler;
use crate::state::{REVISION_CONFLICT, Store};
use crate::tailscale::Provider;

pub struct Api {
    store: Arc<Store>,
    catalog: Arc<StaticCatalog>,
    devices: Arc<Provider>,
    reconciler: Arc<Reconciler>,
    account_limits: Arc<AccountLimits>,
    alerts: Arc<Alerts>,
    notifier: Arc<Notifier>,
    events: Option<Arc<EventLog>>,
    health: Option<Arc<Health>>,
    metrics: Option<Arc<Metrics>>,
    /// `/healthz` fails when no reconcile pass finished for this long.
    liveness_limit: std::time::Duration,
}

/// Replaces the alert channels. A channel that is absent or `null` is turned
/// off; an omitted or empty bot token keeps the saved one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AlertSettingsRequest {
    #[serde(default)]
    telegram: Option<TelegramRequest>,
    #[serde(default)]
    webhook: Option<Webhook>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelegramRequest {
    #[serde(default)]
    bot_token: String,
    chat_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelegramChatsRequest {
    /// Omitted or empty: use the saved token.
    #[serde(default)]
    bot_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MutationRequest {
    revision: u64,
    #[serde(default)]
    server_id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    exit_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsRequest {
    revision: u64,
    /// Omitted: unchanged. `null`: back to the default.
    #[serde(default, deserialize_with = "optional_field")]
    kill_switch: Option<Option<bool>>,
    /// Omitted: unchanged. `null` or `""`: back to the default.
    #[serde(default, deserialize_with = "optional_field")]
    server: Option<Option<String>>,
}

/// Distinguishes an omitted field (`None`) from an explicit `null` (`Some(None)`).
fn optional_field<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl Api {
    pub fn new(
        store: Arc<Store>,
        catalog: Arc<StaticCatalog>,
        devices: Arc<Provider>,
        reconciler: Arc<Reconciler>,
        account_limits: Arc<AccountLimits>,
        alerts: Arc<Alerts>,
        notifier: Arc<Notifier>,
    ) -> Self {
        Self {
            store,
            catalog,
            devices,
            reconciler,
            account_limits,
            alerts,
            notifier,
            events: None,
            health: None,
            metrics: None,
            liveness_limit: std::time::Duration::from_secs(150),
        }
    }

    /// Serves the per-location history for the dashboard's charts.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Serves the health registry, and `/healthz` against `liveness_limit`.
    pub fn with_health(mut self, health: Arc<Health>, liveness_limit: std::time::Duration) -> Self {
        self.health = Some(health);
        self.liveness_limit = liveness_limit;
        self
    }

    /// Records settings changes in, and serves, the event history.
    pub fn with_events(mut self, events: Arc<EventLog>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/v1/status", get(get_status))
            .route("/v1/devices", get(get_devices))
            .route("/v1/catalog", get(get_catalog))
            .route("/v1/exits", get(get_exits).post(create_exit))
            .route("/v1/exits/{exit_id}", put(replace_exit).delete(delete_exit))
            .route(
                "/v1/assignments/{node_id}",
                put(assign_device).delete(disable_device),
            )
            .route(
                "/v1/routes/{node_id}",
                put(route_device).delete(disable_route),
            )
            .route("/v1/dns/{node_id}", put(set_dns).delete(reset_dns))
            .route("/v1/custom-exits", post(import_custom_exit))
            .route("/v1/custom-exits/{server_id}", delete(remove_custom_exit))
            .route("/v1/alerts", get(get_alerts).put(put_alerts))
            .route("/v1/alerts/test", post(test_alerts))
            .route("/v1/alerts/telegram/chats", post(telegram_chats))
            .route("/v1/events", get(get_events).post(post_console_event))
            .route("/v1/health", get(get_health))
            .route("/v1/metrics/history", get(get_history))
            .route("/v1/exits/{exit_id}/diagnose", post(diagnose_exit))
            .route("/v1/support-bundle", get(support_bundle))
            .route("/healthz", get(liveness))
            .route("/readyz", get(readiness))
            .with_state(self.clone())
            .layer(from_fn_with_state(self, record_changes))
            .layer(axum::extract::DefaultBodyLimit::max(1 << 20))
    }

    /// What `record_changes` compares before and after a request.
    fn snapshot(&self) -> audit::Snapshot {
        audit::Snapshot {
            desired: self.store.load().ok(),
            imported: self
                .catalog
                .custom()
                .and_then(|custom| custom.list().ok())
                .unwrap_or_default(),
        }
    }
}

/// Records every settings change in the event history: what changed (by
/// comparing the state before and after), who asked, and from where.
async fn record_changes(State(api): State<Arc<Api>>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let Some(events) = api.events.clone() else {
        return next.run(request).await;
    };
    // Reads, and requests that change nothing, are not recorded.
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        || path == "/v1/events"
        || path == "/v1/alerts/telegram/chats"
        || path.ends_with("/diagnose")
    {
        return next.run(request).await;
    }
    let (actor, client) = {
        let header = |name: &str| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.chars().take(128).collect::<String>())
                .filter(|value| !value.is_empty())
        };
        (header(ACTOR_HEADER), header(CLIENT_HEADER))
    };
    let before = api.snapshot();
    let response = next.run(request).await;
    let status = response.status();
    if !status.is_success() {
        events.record(
            Event::new(
                Severity::Warning,
                Category::Change,
                "settings.rejected",
                format!(
                    "Could not {} (HTTP {})",
                    audit::attempted(method.as_str(), &path),
                    status.as_u16()
                ),
            )
            .by(actor, client),
        );
        return response;
    }
    let after = api.snapshot();
    let names: HashMap<String, String> = api
        .devices
        .devices()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|device| (device.node_id, device.display_name))
        .collect();
    let mut changes = audit::describe(&before, &after, &names);
    if changes.is_empty() && path.starts_with("/v1/alerts") {
        let what = if path.ends_with("/test") {
            "Sent a test alert"
        } else {
            "Changed alert settings"
        };
        changes.push((what.to_owned(), None));
    }
    for (message, subject) in changes {
        let event = Event::new(
            Severity::Info,
            Category::Change,
            "settings.changed",
            message,
        )
        .by(actor.clone(), client.clone());
        events.record(match subject {
            Some(subject) => event.subject(subject),
            None => event,
        });
    }
    response
}

/// Tests one running location now and explains the result.
async fn diagnose_exit(State(api): State<Arc<Api>>, Path(exit_id): Path<String>) -> Response {
    match api.reconciler.diagnose(&exit_id).await {
        Ok(diagnosis) => Json(diagnosis).into_response(),
        Err(error) => error_response(StatusCode::NOT_FOUND, format!("{error:#}")),
    }
}

/// A redacted summary for bug reports: versions, settings, locations, health,
/// alerts, and recent events. Device names become `device-N`, tailnet
/// addresses are hidden, and no keys, tokens, or console users are included.
async fn support_bundle(State(api): State<Arc<Api>>) -> Response {
    let devices = api.devices.devices().await.unwrap_or_default();
    let redactor =
        crate::support::Redactor::new(devices.iter().map(|device| device.display_name.clone()));
    let text = |value: &str| redactor.text(value);
    let desired = api.store.load().ok();
    let (exits, last_error) = api.reconciler.snapshot().await;
    let mut routes: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for assignment in desired.iter().flat_map(|desired| &desired.assignments) {
        let kind = match assignment.exit_id.as_str() {
            crate::domain::DIRECT_ROUTE_ID => "direct",
            crate::domain::LOCAL_ROUTE_ID => "local",
            _ => "vpn",
        };
        *routes.entry(kind).or_default() += 1;
    }
    let checks: Vec<Value> = api
        .health
        .as_ref()
        .map(|health| health.checks())
        .unwrap_or_default()
        .into_iter()
        .map(|check| {
            json!({
                "id": text(&check.id),
                "group": check.group,
                "status": check.status,
                "reason": check.reason,
                "message": text(&check.message),
                "since": check.since,
                "lastOk": check.last_ok,
            })
        })
        .collect();
    let events: Vec<Value> = api
        .events
        .as_ref()
        .map(|events| {
            events.query(&events::Query {
                limit: Some(events::MAX_LIMIT),
                ..Default::default()
            })
        })
        .unwrap_or_default()
        .into_iter()
        .map(|event| {
            json!({
                "time": event.time,
                "severity": event.severity,
                "category": event.category,
                "kind": event.kind,
                "message": text(&event.message),
            })
        })
        .collect();
    let bundle = json!({
        "tailway": crate::VERSION,
        "generated": crate::sessions::now(),
        "gateway": {
            "unassignedPolicy": api.reconciler.unassigned_policy().as_str(),
            "dryRun": api.reconciler.dry_run(),
            "dnsForwarder": api.reconciler.dns().is_some(),
            "tailscaleRunning": api.reconciler.tailscale_running().await,
            "notReady": api.reconciler.not_ready().await,
            "lastError": text(&last_error),
        },
        "devices": devices.len(),
        "routes": routes,
        "locations": exits.iter().map(|exit| json!({
            "name": exit.display_name,
            "country": exit.country,
            "city": exit.city,
            "status": exit.status,
            "reason": exit.status_reason,
            "detail": text(&exit.status_detail),
            "publicIp": exit.public_ip,
        })).collect::<Vec<_>>(),
        "alerts": api.alerts.active().iter().map(|alert| json!({
            "key": text(&alert.key),
            "message": text(&alert.message),
            "since": alert.since,
            "notified": alert.notified,
        })).collect::<Vec<_>>(),
        "health": checks,
        "events": events,
    });
    (
        [(
            axum::http::header::CONTENT_DISPOSITION,
            "attachment; filename=\"tailway-support.json\"",
        )],
        Json(bundle),
    )
        .into_response()
}

/// The last day, one point per minute per location: `[minute, state,
/// probe milliseconds or null, received bit/s, sent bit/s]`.
async fn get_history(State(api): State<Arc<Api>>) -> Response {
    let locations: serde_json::Map<String, Value> = api
        .metrics
        .as_ref()
        .map(|metrics| metrics.history())
        .unwrap_or_default()
        .into_iter()
        .map(|(name, points)| {
            let rows = points
                .iter()
                .map(|point| {
                    json!([
                        point.minute,
                        point.state,
                        point.probe_ms,
                        point.received_bps,
                        point.sent_bps
                    ])
                })
                .collect();
            (name, Value::Array(rows))
        })
        .collect();
    Json(json!({ "locations": locations })).into_response()
}

/// Every health check, and the worst status among them.
async fn get_health(State(api): State<Arc<Api>>) -> Response {
    let Some(health) = &api.health else {
        return Json(json!({ "status": "unknown", "checks": [] })).into_response();
    };
    Json(json!({ "status": health.overall(), "checks": health.checks() })).into_response()
}

/// Liveness, for the container healthcheck: the reconcile loop still runs.
/// Its result does not matter here; a failing gateway is not fixed by a restart.
async fn liveness(State(api): State<Arc<Api>>) -> Response {
    let since = api.reconciler.since_last_pass();
    let alive = since <= api.liveness_limit;
    let status = if alive {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({ "alive": alive, "lastPassSecondsAgo": since.as_secs() })),
    )
        .into_response()
}

/// Readiness: Tailscale up, rules applied, DNS answering.
async fn readiness(State(api): State<Arc<Api>>) -> Response {
    let reasons = api.reconciler.not_ready().await;
    let status = if reasons.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({ "ready": reasons.is_empty(), "reasons": reasons })),
    )
        .into_response()
}

async fn get_events(State(api): State<Arc<Api>>, Query(query): Query<events::Query>) -> Response {
    let events = api
        .events
        .as_ref()
        .map(|events| events.query(&query))
        .unwrap_or_default();
    Json(json!({ "events": events })).into_response()
}

/// Account events from the console (sign-ins, password changes). The console
/// never forwards browser requests here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsoleEvent {
    severity: Severity,
    kind: String,
    message: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    client: Option<String>,
}

async fn post_console_event(
    State(api): State<Arc<Api>>,
    Json(event): Json<ConsoleEvent>,
) -> Response {
    let valid_kind = event.kind.len() <= 64
        && event.kind.strip_prefix("console.").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
    if !valid_kind {
        return error_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("console events have kinds like console.sign_in"),
        );
    }
    let short = |value: Option<String>| value.map(|value| value.chars().take(128).collect());
    let Some(events) = &api.events else {
        return StatusCode::NO_CONTENT.into_response();
    };
    events.record(
        Event::new(event.severity, Category::Access, &event.kind, event.message)
            .by(short(event.actor), short(event.client)),
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn get_status(State(api): State<Arc<Api>>) -> Response {
    let desired = match api.store.load() {
        Ok(desired) => desired,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let (exits, last_error) = api.reconciler.snapshot().await;
    let applied_revision = api.reconciler.applied_revision().await;
    let exit_limit = api.account_limits.exit_limit().await.ok().flatten();
    json_response(
        StatusCode::OK,
        json!({
            "version": crate::VERSION,
            "schemaVersion": SCHEMA_VERSION,
            "revision": desired.revision,
            "appliedRevision": applied_revision,
            "state": if last_error.is_empty() { "healthy" } else { "failed" },
            "lastError": last_error,
            "activeExits": exits.len(),
            "exitLimit": exit_limit,
            "dryRun": api.reconciler.dry_run(),
            "unassignedPolicy": api.reconciler.unassigned_policy().as_str(),
            "alerts": api.alerts.active(),
            "dns": api.reconciler.dns().map(|resolver| {
                let defaults = resolver.defaults();
                json!({
                    "enabled": true,
                    "defaultServer": defaults.server.to_string(),
                    "killSwitchDefault": defaults.kill_switch,
                })
            }).unwrap_or_else(|| json!({"enabled": false})),
        }),
    )
}

async fn get_devices(State(api): State<Arc<Api>>) -> Response {
    let devices = match api.devices.devices().await {
        Ok(devices) => devices,
        Err(error) => return error_response(StatusCode::SERVICE_UNAVAILABLE, error),
    };
    let desired = match api.store.load() {
        Ok(desired) => desired,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let dns_settings: HashMap<_, _> = desired
        .dns
        .iter()
        .map(|setting| (setting.node_id.clone(), setting.clone()))
        .collect();
    let mut assignments: HashMap<_, _> = desired
        .assignments
        .into_iter()
        .map(|assignment| (assignment.node_id, assignment.exit_id))
        .collect();
    let resolver = api.reconciler.dns();
    let usage = api.reconciler.exit_usage().await;
    let mut result: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let exit_id = assignments.remove(&device.node_id).unwrap_or_default();
            let dns = resolver
                .map(|resolver| device_dns(resolver, &device, dns_settings.get(&device.node_id)));
            let last_exit_traffic = device.addresses.iter().find_map(|address| match address {
                std::net::IpAddr::V4(address) => usage.get(address).copied(),
                std::net::IpAddr::V6(_) => None,
            });
            let mut value = serde_json::to_value(device).expect("serialize device");
            if !exit_id.is_empty() {
                value["exitId"] = json!(exit_id);
            }
            if let Some(dns) = dns {
                value["dns"] = dns;
            }
            // Traffic to the Internet through this gateway means the device has
            // selected it as its exit node (Tailscale does not report that).
            value["exitNode"] = json!({
                "inUse": last_exit_traffic.is_some(),
                "lastTrafficSecondsAgo": last_exit_traffic,
                "windowSeconds": crate::usage::WINDOW.as_secs(),
            });
            value
        })
        .collect();
    // Assignments for nodes that left the tailnet are listed so they can be cleared.
    let mut missing: Vec<_> = assignments.into_iter().collect();
    missing.sort();
    result.extend(missing.into_iter().map(|(node_id, exit_id)| {
        json!({
            "nodeId": node_id,
            "displayName": "",
            "addresses": [],
            "online": false,
            "active": false,
            "missing": true,
            "exitId": exit_id,
        })
    }));
    json_response(StatusCode::OK, json!(result))
}

async fn get_catalog(State(api): State<Arc<Api>>) -> Response {
    match api.catalog.list() {
        Ok(servers) => json_response(
            StatusCode::OK,
            json!({"adapter": "static", "servers": servers}),
        ),
        Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, error),
    }
}

async fn import_custom_exit(
    State(api): State<Arc<Api>>,
    Json(import): Json<crate::custom::Import>,
) -> Response {
    let Some(custom) = api.catalog.custom() else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "importing configurations is not enabled",
        );
    };
    match custom.add(import) {
        Ok(server) => {
            tracing::info!(server = %server.id, provider = %server.provider, country = %server.country, "WireGuard configuration imported");
            json_response(StatusCode::CREATED, json!({"server": server}))
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, format!("{error:#}")),
    }
}

/// Removes an imported location. Refused while devices use it; a tunnel that
/// no device uses is stopped first.
async fn remove_custom_exit(
    State(api): State<Arc<Api>>,
    Path(server_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let Some(custom) = api.catalog.custom() else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "importing configurations is not enabled",
        );
    };
    if !custom.contains(&server_id) {
        return error_response(StatusCode::NOT_FOUND, "unknown imported location");
    }
    let result = api.store.update(input.revision, |desired| {
        let exit_ids: HashSet<String> = desired
            .exits
            .iter()
            .filter(|exit| exit.server_id == server_id)
            .map(|exit| exit.id.clone())
            .collect();
        if desired
            .assignments
            .iter()
            .any(|assignment| exit_ids.contains(&assignment.exit_id))
        {
            anyhow::bail!("devices still use this location; choose another route for them first");
        }
        desired.exits.retain(|exit| !exit_ids.contains(&exit.id));
        Ok(())
    });
    if result.is_ok()
        && let Err(error) = custom.remove(&server_id)
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }
    finish_mutation(api, result).await
}

async fn get_exits(State(api): State<Arc<Api>>) -> Response {
    let mut desired = match api.store.load() {
        Ok(desired) => desired,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let (runtime_exits, _) = api.reconciler.snapshot().await;
    let mut observed: HashMap<_, _> = runtime_exits
        .into_iter()
        .map(|exit| (exit.id.clone(), exit))
        .collect();
    for exit in &mut desired.exits {
        if let Some(runtime) = observed.remove(&exit.id) {
            exit.status = runtime.status;
            exit.status_detail = runtime.status_detail;
            exit.public_ip = runtime.public_ip;
        }
    }
    json_response(
        StatusCode::OK,
        json!({"revision": desired.revision, "exits": desired.exits}),
    )
}

async fn create_exit(
    State(api): State<Arc<Api>>,
    Json(mut input): Json<MutationRequest>,
) -> Response {
    let exit_limit = match api.account_limits.exit_limit().await {
        Ok(exit_limit) => exit_limit,
        Err(error) => return error_response(StatusCode::SERVICE_UNAVAILABLE, error),
    };
    let server = match api.catalog.resolve(&input.server_id) {
        Ok(server) => server,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    if input.display_name.trim().is_empty() {
        input.display_name = server.name.clone();
    }
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let exit_id = format!("exit-{}", hex::encode(random));
    let custom_servers = custom_server_ids(&api);
    let limit = proton_limit(&server, exit_limit, &custom_servers);
    let result = api.store.update(input.revision, |desired| {
        enforce_exit_limit(desired, limit)?;
        desired.exits.push(Exit {
            id: exit_id,
            display_name: input.display_name,
            server_id: server.id,
            country: server.country,
            city: server.city,
            status: ExitStatus::Pending,
            ..Exit::default()
        });
        Ok(())
    });
    finish_mutation(api, result).await
}

async fn replace_exit(
    State(api): State<Arc<Api>>,
    Path(exit_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let server = match api.catalog.resolve(&input.server_id) {
        Ok(server) => server,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    let result = api.store.update(input.revision, |desired| {
        let exit = desired
            .exits
            .iter_mut()
            .find(|exit| exit.id == exit_id)
            .ok_or_else(|| anyhow::anyhow!("unknown exit"))?;
        let display_name = if input.display_name.trim().is_empty() {
            exit.display_name.clone()
        } else {
            input.display_name
        };
        *exit = Exit {
            id: exit_id,
            display_name,
            server_id: server.id,
            country: server.country,
            city: server.city,
            status: ExitStatus::Pending,
            ..Exit::default()
        };
        Ok(())
    });
    finish_mutation(api, result).await
}

async fn delete_exit(
    State(api): State<Arc<Api>>,
    Path(exit_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let result = api.store.update(input.revision, |desired| {
        if desired
            .assignments
            .iter()
            .any(|assignment| assignment.exit_id == exit_id)
        {
            anyhow::bail!("disable or reassign devices before deleting this exit");
        }
        let previous_len = desired.exits.len();
        desired.exits.retain(|exit| exit.id != exit_id);
        if desired.exits.len() == previous_len {
            anyhow::bail!("unknown exit");
        }
        Ok(())
    });
    finish_mutation(api, result).await
}

async fn assign_device(
    State(api): State<Arc<Api>>,
    Path(node_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let devices = match api.devices.devices().await {
        Ok(devices) => devices,
        Err(error) => return error_response(StatusCode::SERVICE_UNAVAILABLE, error),
    };
    if !devices.iter().any(|device| device.node_id == node_id) {
        return error_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("unknown Tailscale node"),
        );
    }
    let result = api.store.update(input.revision, |desired| {
        if !is_builtin_route(&input.exit_id)
            && !desired.exits.iter().any(|exit| exit.id == input.exit_id)
        {
            anyhow::bail!("unknown exit");
        }
        set_assignment(desired, &node_id, &input.exit_id);
        Ok(())
    });
    finish_mutation(api, result).await
}

async fn disable_device(
    State(api): State<Arc<Api>>,
    Path(node_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let result = api.store.update(input.revision, |desired| {
        disable_node_route(desired, &node_id);
        Ok(())
    });
    finish_mutation(api, result).await
}

async fn route_device(
    State(api): State<Arc<Api>>,
    Path(node_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let devices = match api.devices.devices().await {
        Ok(devices) => devices,
        Err(error) => return error_response(StatusCode::SERVICE_UNAVAILABLE, error),
    };
    if !devices.iter().any(|device| device.node_id == node_id) {
        return error_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("unknown Tailscale node"),
        );
    }
    let new_exit_id = random_exit_id();
    let exit_limit = match api.account_limits.exit_limit().await {
        Ok(exit_limit) => exit_limit,
        Err(error) => return error_response(StatusCode::SERVICE_UNAVAILABLE, error),
    };
    let custom_servers = custom_server_ids(&api);
    let result = api.store.update(input.revision, |desired| {
        if is_builtin_route(&input.server_id) {
            set_assignment(desired, &node_id, &input.server_id);
            Ok(())
        } else {
            let server = api.catalog.resolve(&input.server_id)?;
            let limit = proton_limit(&server, exit_limit, &custom_servers);
            route_node_to_server(desired, &node_id, &server, &new_exit_id, limit)
        }
    });
    finish_mutation(api, result).await
}

async fn disable_route(
    State(api): State<Arc<Api>>,
    Path(node_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let result = api.store.update(input.revision, |desired| {
        disable_node_route(desired, &node_id);
        Ok(())
    });
    finish_mutation(api, result).await
}

fn device_dns(
    resolver: &dns::Resolver,
    device: &crate::domain::Device,
    setting: Option<&NodeDns>,
) -> Value {
    let defaults = resolver.defaults();
    let (server, kill_switch) = dns::effective(setting, defaults);
    let resolution = device.addresses.iter().find_map(|address| match address {
        std::net::IpAddr::V4(address) => Some(resolver.resolve(*address)),
        std::net::IpAddr::V6(_) => None,
    });
    json!({
        "resolution": resolution.as_ref().map_or("server", dns::Resolution::kind),
        "server": server.to_string(),
        "killSwitch": kill_switch,
        "customServer": setting.and_then(|setting| setting.server).map(|server| server.to_string()),
        "customKillSwitch": setting.and_then(|setting| setting.kill_switch),
        "defaultServer": defaults.server.to_string(),
    })
}

async fn set_dns(
    State(api): State<Arc<Api>>,
    Path(node_id): Path<String>,
    Json(input): Json<DnsRequest>,
) -> Response {
    let server = match input.server {
        None => None,
        Some(value) => match parse_dns_server(value.as_deref().unwrap_or("")) {
            Ok(server) => Some(server),
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        },
    };
    let result = api.store.update(input.revision, |desired| {
        set_node_dns(desired, &node_id, input.kill_switch, server);
        Ok(())
    });
    finish_mutation(api, result).await
}

async fn reset_dns(
    State(api): State<Arc<Api>>,
    Path(node_id): Path<String>,
    Json(input): Json<MutationRequest>,
) -> Response {
    let result = api.store.update(input.revision, |desired| {
        desired.dns.retain(|setting| setting.node_id != node_id);
        Ok(())
    });
    finish_mutation(api, result).await
}

/// Empty means "use the default". Otherwise a unicast IPv4 resolver address.
fn parse_dns_server(value: &str) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let server: std::net::Ipv4Addr = value
        .parse()
        .map_err(|_| anyhow::anyhow!("DNS server must be an IPv4 address"))?;
    if server.is_unspecified()
        || server.is_loopback()
        || server.is_multicast()
        || server.is_broadcast()
        || dns::is_tailnet(std::net::IpAddr::V4(server))
    {
        anyhow::bail!("DNS server {server} is not a usable resolver address");
    }
    Ok(Some(server))
}

fn set_node_dns(
    desired: &mut DesiredState,
    node_id: &str,
    kill_switch: Option<Option<bool>>,
    server: Option<Option<std::net::Ipv4Addr>>,
) {
    let index = match desired
        .dns
        .iter()
        .position(|setting| setting.node_id == node_id)
    {
        Some(index) => index,
        None => {
            desired.dns.push(NodeDns {
                node_id: node_id.into(),
                ..NodeDns::default()
            });
            desired.dns.len() - 1
        }
    };
    let setting = &mut desired.dns[index];
    if let Some(kill_switch) = kill_switch {
        setting.kill_switch = kill_switch;
    }
    if let Some(server) = server {
        setting.server = server;
    }
    if setting.kill_switch.is_none() && setting.server.is_none() {
        desired.dns.remove(index);
    }
}

fn route_node_to_server(
    desired: &mut DesiredState,
    node_id: &str,
    server: &Server,
    new_exit_id: &str,
    exit_limit: Option<ProtonLimit<'_>>,
) -> anyhow::Result<()> {
    let previous_exit_id = desired
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == node_id)
        .map(|assignment| assignment.exit_id.clone());

    let exit_id = if let Some(exit) = desired
        .exits
        .iter()
        .find(|exit| exit.server_id == server.id)
    {
        exit.id.clone()
    } else {
        let replaceable = previous_exit_id
            .as_ref()
            .filter(|exit_id| !is_builtin_route(exit_id))
            .and_then(|exit_id| {
                let shared = desired.assignments.iter().any(|assignment| {
                    assignment.node_id != node_id && assignment.exit_id == *exit_id
                });
                (!shared).then_some(exit_id.clone())
            });
        if replaceable.is_none() {
            enforce_exit_limit(desired, exit_limit)?;
        }
        let exit_id = replaceable.unwrap_or_else(|| new_exit_id.to_owned());
        let replacement = Exit {
            id: exit_id.clone(),
            display_name: server.name.clone(),
            server_id: server.id.clone(),
            country: server.country.clone(),
            city: server.city.clone(),
            status: ExitStatus::Pending,
            ..Exit::default()
        };
        if let Some(exit) = desired.exits.iter_mut().find(|exit| exit.id == exit_id) {
            *exit = replacement;
        } else {
            desired.exits.push(replacement);
        }
        exit_id
    };

    match desired
        .assignments
        .iter_mut()
        .find(|assignment| assignment.node_id == node_id)
    {
        Some(assignment) => assignment.exit_id = exit_id,
        None => desired.assignments.push(Assignment {
            node_id: node_id.to_owned(),
            exit_id,
        }),
    }
    remove_unused_previous_exit(desired, previous_exit_id.as_deref());
    Ok(())
}

/// Proton's connection limit. Imported WireGuard tunnels do not count toward it.
#[derive(Clone, Copy)]
struct ProtonLimit<'a> {
    max: usize,
    custom_servers: &'a HashSet<String>,
}

/// The limit that applies when adding a tunnel to `server`: none for imported ones.
fn proton_limit<'a>(
    server: &Server,
    exit_limit: Option<usize>,
    custom_servers: &'a HashSet<String>,
) -> Option<ProtonLimit<'a>> {
    match (server.source, exit_limit) {
        (ServerSource::Proton, Some(max)) => Some(ProtonLimit {
            max,
            custom_servers,
        }),
        _ => None,
    }
}

fn enforce_exit_limit(
    desired: &DesiredState,
    limit: Option<ProtonLimit<'_>>,
) -> anyhow::Result<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let active = desired
        .exits
        .iter()
        .filter(|exit| !limit.custom_servers.contains(&exit.server_id))
        .count();
    if active >= limit.max {
        anyhow::bail!(
            "Proton account connection limit reached ({active}/{})",
            limit.max
        );
    }
    Ok(())
}

fn custom_server_ids(api: &Api) -> HashSet<String> {
    api.catalog
        .custom()
        .and_then(|custom| custom.list().ok())
        .unwrap_or_default()
        .into_iter()
        .map(|server| server.id)
        .collect()
}

fn disable_node_route(desired: &mut DesiredState, node_id: &str) {
    let previous_exit_id = desired
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == node_id)
        .map(|assignment| assignment.exit_id.clone());
    desired
        .assignments
        .retain(|assignment| assignment.node_id != node_id);
    remove_unused_previous_exit(desired, previous_exit_id.as_deref());
}

/// Points a node at an exit or built-in route and garbage-collects the exit it left.
fn set_assignment(desired: &mut DesiredState, node_id: &str, exit_id: &str) {
    let previous_exit_id = desired
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == node_id)
        .map(|assignment| assignment.exit_id.clone());
    match desired
        .assignments
        .iter_mut()
        .find(|assignment| assignment.node_id == node_id)
    {
        Some(assignment) => assignment.exit_id = exit_id.into(),
        None => desired.assignments.push(Assignment {
            node_id: node_id.into(),
            exit_id: exit_id.into(),
        }),
    }
    if previous_exit_id.as_deref() != Some(exit_id) {
        remove_unused_previous_exit(desired, previous_exit_id.as_deref());
    }
}

fn remove_unused_previous_exit(desired: &mut DesiredState, exit_id: Option<&str>) {
    let Some(exit_id) = exit_id else {
        return;
    };
    if is_builtin_route(exit_id) {
        return;
    }
    if !desired
        .assignments
        .iter()
        .any(|assignment| assignment.exit_id == exit_id)
    {
        desired.exits.retain(|exit| exit.id != exit_id);
    }
}

fn random_exit_id() -> String {
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    format!("exit-{}", hex::encode(random))
}

async fn finish_mutation(
    api: Arc<Api>,
    result: anyhow::Result<crate::domain::DesiredState>,
) -> Response {
    let desired = match result {
        Ok(desired) => desired,
        Err(error) => {
            let status = if error.to_string() == REVISION_CONFLICT {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            return error_response(status, error);
        }
    };
    match api.reconciler.reconcile().await {
        Ok(()) => json_response(
            StatusCode::ACCEPTED,
            json!({"revision": desired.revision, "state": "healthy"}),
        ),
        Err(error) => json_response(
            StatusCode::ACCEPTED,
            json!({"revision": desired.revision, "state": "failed", "reason": error.to_string()}),
        ),
    }
}

fn alert_settings_view(settings: &Settings) -> Value {
    json!({
        "telegram": settings.telegram.as_ref().map(|telegram| json!({
            "chatId": telegram.chat_id,
            "botTokenHint": telegram.token_hint(),
        })),
        "webhook": settings.webhook,
    })
}

async fn get_alerts(State(api): State<Arc<Api>>) -> Response {
    let settings = api.notifier.settings().get();
    json_response(
        StatusCode::OK,
        json!({
            "settings": alert_settings_view(&settings),
            "active": api.alerts.active(),
        }),
    )
}

fn merge_alert_settings(
    current: &Settings,
    request: AlertSettingsRequest,
) -> anyhow::Result<Settings> {
    let telegram = match request.telegram {
        None => None,
        Some(telegram) => {
            let bot_token = if telegram.bot_token.trim().is_empty() {
                current
                    .telegram
                    .as_ref()
                    .map(|saved| saved.bot_token.clone())
                    .ok_or_else(|| anyhow::anyhow!("enter the Telegram bot token"))?
            } else {
                telegram.bot_token.trim().to_owned()
            };
            Some(Telegram {
                bot_token,
                chat_id: telegram.chat_id.trim().to_owned(),
            })
        }
    };
    let settings = Settings {
        telegram,
        webhook: request.webhook.map(|webhook| Webhook {
            url: webhook.url.trim().to_owned(),
            format: webhook.format,
        }),
    };
    settings.validate()?;
    Ok(settings)
}

async fn put_alerts(
    State(api): State<Arc<Api>>,
    Json(request): Json<AlertSettingsRequest>,
) -> Response {
    let settings = match merge_alert_settings(&api.notifier.settings().get(), request) {
        Ok(settings) => settings,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(error) = api.notifier.settings().replace(settings.clone()) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, error);
    }
    tracing::info!(channels = ?notify::channels(&settings), "alert channels updated");
    json_response(
        StatusCode::OK,
        json!({"settings": alert_settings_view(&settings)}),
    )
}

async fn test_alerts(State(api): State<Arc<Api>>) -> Response {
    if api.notifier.settings().get().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "no alert channel is configured");
    }
    let results = api
        .notifier
        .send(&Notification {
            key: "test".into(),
            title: "Test notification".into(),
            message: "Alerts from the gateway will arrive here.".into(),
            kind: "info",
        })
        .await;
    json_response(StatusCode::OK, json!({"results": results}))
}

async fn telegram_chats(
    State(api): State<Arc<Api>>,
    Json(request): Json<TelegramChatsRequest>,
) -> Response {
    let token = if request.bot_token.trim().is_empty() {
        match api.notifier.settings().get().telegram {
            Some(telegram) => telegram.bot_token,
            None => return error_response(StatusCode::BAD_REQUEST, "enter the Telegram bot token"),
        }
    } else {
        request.bot_token.trim().to_owned()
    };
    match api.notifier.telegram_chats(&token).await {
        Ok(chats) => json_response(StatusCode::OK, json!({"chats": chats})),
        Err(error) => error_response(StatusCode::BAD_GATEWAY, format!("{error:#}")),
    }
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn error_response(status: StatusCode, error: impl std::fmt::Display) -> Response {
    json_response(status, json!({"error": error.to_string()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

    fn alert_request(value: Value) -> AlertSettingsRequest {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn alert_settings_keep_the_saved_token_and_turn_off_omitted_channels() {
        let saved = merge_alert_settings(
            &Settings::default(),
            alert_request(json!({"telegram": {"botToken": TOKEN, "chatId": "42"}, "webhook": {"url": "https://ntfy.sh/topic", "format": "ntfy"}})),
        )
        .unwrap();
        let updated = merge_alert_settings(
            &saved,
            alert_request(json!({"telegram": {"chatId": "-100123"}})),
        )
        .unwrap();
        assert_eq!(updated.telegram.as_ref().unwrap().bot_token, TOKEN);
        assert_eq!(updated.telegram.as_ref().unwrap().chat_id, "-100123");
        assert!(updated.webhook.is_none());
        assert!(
            merge_alert_settings(&saved, alert_request(json!({})))
                .unwrap()
                .is_empty()
        );
        assert!(
            merge_alert_settings(
                &Settings::default(),
                alert_request(json!({"telegram": {"chatId": "42"}}))
            )
            .unwrap_err()
            .to_string()
            .contains("bot token")
        );
        assert!(serde_json::from_value::<AlertSettingsRequest>(json!({"email": {}})).is_err());
    }

    #[test]
    fn alert_settings_view_never_contains_the_token() {
        let settings = merge_alert_settings(
            &Settings::default(),
            alert_request(json!({"telegram": {"botToken": TOKEN, "chatId": "42"}})),
        )
        .unwrap();
        let view = alert_settings_view(&settings).to_string();
        assert!(!view.contains("AAHdq"));
        assert!(view.contains("bot 123456789"));
    }
    use crate::domain::{DIRECT_ROUTE_ID, LOCAL_ROUTE_ID};

    fn server(id: &str) -> Server {
        Server {
            id: id.into(),
            source: ServerSource::Proton,
            provider: "Proton VPN".into(),
            country: "CH".into(),
            city: "Zurich".into(),
            name: id.into(),
            load: None,
            features: Vec::new(),
            config_file: String::new(),
        }
    }

    #[test]
    fn direct_routes_reuse_and_collect_exits() {
        let mut desired = DesiredState::default();
        route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-a", None).unwrap();
        route_node_to_server(&mut desired, "node-b", &server("ch-1"), "exit-b", None).unwrap();
        assert_eq!(desired.exits.len(), 1);
        assert_eq!(desired.assignments[1].exit_id, "exit-a");

        route_node_to_server(&mut desired, "node-a", &server("us-1"), "exit-us", None).unwrap();
        assert_eq!(desired.exits.len(), 2);
        disable_node_route(&mut desired, "node-b");
        assert_eq!(desired.exits.len(), 1);
        assert_eq!(desired.exits[0].server_id, "us-1");
    }

    #[test]
    fn direct_route_supports_more_than_two_distinct_exits() {
        let mut desired = DesiredState::default();
        route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-ch", None).unwrap();
        route_node_to_server(&mut desired, "node-b", &server("ch-1"), "unused", None).unwrap();
        route_node_to_server(&mut desired, "node-c", &server("us-1"), "exit-us", None).unwrap();
        route_node_to_server(&mut desired, "node-d", &server("de-1"), "exit-de", None).unwrap();
        assert_eq!(desired.exits.len(), 3);
        assert_eq!(desired.assignments[3].exit_id, "exit-de");
    }

    #[test]
    fn builtin_routes_collect_the_previous_vpn_exit() {
        for route in [LOCAL_ROUTE_ID, DIRECT_ROUTE_ID] {
            let mut desired = DesiredState::default();
            route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-ch", None).unwrap();
            set_assignment(&mut desired, "node-a", route);
            assert!(desired.exits.is_empty());
            assert_eq!(desired.assignments[0].exit_id, route);
        }
    }

    #[test]
    fn leaving_a_builtin_route_creates_a_real_exit() {
        for route in [LOCAL_ROUTE_ID, DIRECT_ROUTE_ID] {
            let mut desired = DesiredState::default();
            set_assignment(&mut desired, "node-a", route);
            route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-ch", None).unwrap();
            assert_eq!(desired.exits.len(), 1);
            assert_eq!(desired.exits[0].id, "exit-ch");
            assert_eq!(desired.assignments[0].exit_id, "exit-ch");
        }
    }

    #[test]
    fn node_dns_settings_update_and_clear() {
        let mut desired = DesiredState::default();
        let router = std::net::Ipv4Addr::new(192, 168, 0, 1);
        set_node_dns(&mut desired, "node-a", Some(Some(false)), None);
        set_node_dns(&mut desired, "node-a", None, Some(Some(router)));
        assert_eq!(desired.dns.len(), 1);
        assert_eq!(desired.dns[0].kill_switch, Some(false));
        assert_eq!(desired.dns[0].server, Some(router));
        set_node_dns(&mut desired, "node-a", Some(None), Some(None));
        assert!(desired.dns.is_empty(), "all defaults removes the entry");
    }

    #[test]
    fn validates_dns_servers() {
        assert_eq!(parse_dns_server("").unwrap(), None);
        assert_eq!(
            parse_dns_server(" 192.168.0.1 ").unwrap(),
            Some(std::net::Ipv4Addr::new(192, 168, 0, 1))
        );
        for bad in [
            "dns.example",
            "::1",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "100.76.60.35",
        ] {
            assert!(parse_dns_server(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn disabling_a_node_collects_its_unshared_exit() {
        let mut desired = DesiredState::default();
        route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-ch", None).unwrap();
        route_node_to_server(&mut desired, "node-b", &server("ch-1"), "unused", None).unwrap();
        disable_node_route(&mut desired, "node-a");
        assert_eq!(desired.exits.len(), 1);
        disable_node_route(&mut desired, "node-b");
        assert!(desired.exits.is_empty());
        assert!(desired.assignments.is_empty());
    }

    #[test]
    fn proton_quota_blocks_only_a_new_distinct_exit() {
        let mut desired = DesiredState::default();
        let none = HashSet::new();
        let limit = proton_limit(&server("ch-1"), Some(1), &none);
        route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-ch", limit).unwrap();
        route_node_to_server(&mut desired, "node-b", &server("ch-1"), "unused", limit).unwrap();
        let error = route_node_to_server(&mut desired, "node-c", &server("us-1"), "exit-us", limit)
            .unwrap_err();
        assert!(error.to_string().contains("connection limit reached (1/1)"));
        assert_eq!(desired.exits.len(), 1);
    }

    #[test]
    fn imported_tunnels_neither_count_nor_are_limited() {
        let mut desired = DesiredState::default();
        let custom = HashSet::from(["custom-aaaaaaaaaaaa".to_owned()]);
        let mut home = server("custom-aaaaaaaaaaaa");
        home.source = ServerSource::Custom;
        // An imported tunnel is not limited even when Proton is full...
        assert!(proton_limit(&home, Some(1), &custom).is_none());
        route_node_to_server(
            &mut desired,
            "node-a",
            &home,
            "exit-home",
            proton_limit(&home, Some(1), &custom),
        )
        .unwrap();
        // ...and does not use up a Proton connection.
        let proton = server("ch-1");
        route_node_to_server(
            &mut desired,
            "node-b",
            &proton,
            "exit-ch",
            proton_limit(&proton, Some(1), &custom),
        )
        .unwrap();
        assert_eq!(desired.exits.len(), 2);
        let error = route_node_to_server(
            &mut desired,
            "node-c",
            &server("us-1"),
            "exit-us",
            proton_limit(&server("us-1"), Some(1), &custom),
        )
        .unwrap_err();
        assert!(error.to_string().contains("(1/1)"));
    }
}
