use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::catalog::StaticCatalog;
use crate::domain::{
    Assignment, DesiredState, Exit, ExitStatus, SCHEMA_VERSION, Server, is_builtin_route,
};
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

impl Api {
    pub fn new(
        store: Arc<Store>,
        catalog: Arc<StaticCatalog>,
        devices: Arc<Provider>,
        reconciler: Arc<Reconciler>,
        account_limits: Arc<AccountLimits>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            catalog,
            devices,
            reconciler,
            account_limits,
        })
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
            .with_state(self)
            .layer(axum::extract::DefaultBodyLimit::max(1 << 20))
    }
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
            "schemaVersion": SCHEMA_VERSION,
            "revision": desired.revision,
            "appliedRevision": applied_revision,
            "state": if last_error.is_empty() { "healthy" } else { "failed" },
            "lastError": last_error,
            "activeExits": exits.len(),
            "exitLimit": exit_limit,
            "dryRun": api.reconciler.dry_run(),
            "unassignedPolicy": api.reconciler.unassigned_policy().as_str(),
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
    let mut assignments: HashMap<_, _> = desired
        .assignments
        .into_iter()
        .map(|assignment| (assignment.node_id, assignment.exit_id))
        .collect();
    let mut result: Vec<_> = devices
        .into_iter()
        .map(|device| {
            let exit_id = assignments.remove(&device.node_id).unwrap_or_default();
            let mut value = serde_json::to_value(device).expect("serialize device");
            if !exit_id.is_empty() {
                value["exitId"] = json!(exit_id);
            }
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

async fn get_exits(State(api): State<Arc<Api>>) -> Response {
    let mut desired = match api.store.load() {
        Ok(desired) => desired,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let (runtime_exits, _) = api.reconciler.snapshot().await;
    let statuses: HashMap<_, _> = runtime_exits
        .into_iter()
        .map(|exit| (exit.id, exit.status))
        .collect();
    for exit in &mut desired.exits {
        if let Some(status) = statuses.get(&exit.id) {
            exit.status = status.clone();
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
    let result = api.store.update(input.revision, |desired| {
        enforce_exit_limit(desired.exits.len(), exit_limit)?;
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
    let result = api.store.update(input.revision, |desired| {
        if is_builtin_route(&input.server_id) {
            set_assignment(desired, &node_id, &input.server_id);
            Ok(())
        } else {
            let server = api.catalog.resolve(&input.server_id)?;
            route_node_to_server(desired, &node_id, &server, &new_exit_id, exit_limit)
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

fn route_node_to_server(
    desired: &mut DesiredState,
    node_id: &str,
    server: &Server,
    new_exit_id: &str,
    exit_limit: Option<usize>,
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
            enforce_exit_limit(desired.exits.len(), exit_limit)?;
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

fn enforce_exit_limit(active_exits: usize, exit_limit: Option<usize>) -> anyhow::Result<()> {
    if let Some(exit_limit) = exit_limit
        && active_exits >= exit_limit
    {
        anyhow::bail!("Proton account connection limit reached ({active_exits}/{exit_limit})");
    }
    Ok(())
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
    use crate::domain::{DIRECT_ROUTE_ID, LOCAL_ROUTE_ID};

    fn server(id: &str) -> Server {
        Server {
            id: id.into(),
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
        route_node_to_server(&mut desired, "node-a", &server("ch-1"), "exit-ch", Some(1)).unwrap();
        route_node_to_server(&mut desired, "node-b", &server("ch-1"), "unused", Some(1)).unwrap();
        let error =
            route_node_to_server(&mut desired, "node-c", &server("us-1"), "exit-us", Some(1))
                .unwrap_err();
        assert!(error.to_string().contains("connection limit reached (1/1)"));
        assert_eq!(desired.exits.len(), 1);
    }
}
