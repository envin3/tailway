use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bcrypt::verify;
use http_body_util::Full;
use hyper::Request as HyperRequest;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use subtle::ConstantTimeEq;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::info;

const INDEX_HTML: &str = include_str!("../../cmd/gateway-ui/static/index.html");
const APP_JS: &str = include_str!("../../cmd/gateway-ui/static/app.js");
const STYLES_CSS: &str = include_str!("../../cmd/gateway-ui/static/styles.css");

struct UiState {
    socket_path: PathBuf,
    proton_socket_path: PathBuf,
    password_hash: String,
    csrf_token: String,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let password_hash = tokio::fs::read_to_string(required_environment("PASSWORD_HASH_FILE")?)
        .await
        .context("read password hash")?;
    let csrf_token = tokio::fs::read_to_string(required_environment("CSRF_TOKEN_FILE")?)
        .await
        .context("read CSRF token")?;
    let csrf_token = csrf_token.trim().to_owned();
    if csrf_token.len() < 32 {
        bail!("CSRF token must be at least 32 bytes");
    }
    let state = Arc::new(UiState {
        socket_path: PathBuf::from(environment(
            "CONTROL_SOCKET",
            "/run/tailscale-exit-policy-router/control.sock",
        )),
        proton_socket_path: PathBuf::from(environment(
            "PROTON_BROKER_SOCKET",
            "/run/tailscale-exit-policy-router/proton.sock",
        )),
        password_hash: password_hash.trim().to_owned(),
        csrf_token,
        failures: Mutex::new(HashMap::new()),
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/session", get(session))
        .route("/v1/proton/{*path}", any(proxy_proton))
        .route("/v1/{*path}", any(proxy_agent))
        .with_state(state.clone())
        .layer(from_fn_with_state(state, authenticate))
        .layer(from_fn(security_headers));

    let address = parse_address(&environment("LISTEN_ADDRESS", ":8443"))?;
    let tls = RustlsConfig::from_pem_file(
        required_environment("TLS_CERT_FILE")?,
        required_environment("TLS_KEY_FILE")?,
    )
    .await?;
    info!(%address, "gateway console ready");
    axum_server::bind_rustls(address, tls)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> Response {
    with_content_type(APP_JS, "text/javascript; charset=utf-8")
}

async fn styles_css() -> Response {
    with_content_type(STYLES_CSS, "text/css; charset=utf-8")
}

async fn session(State(state): State<Arc<UiState>>) -> Response {
    let body = serde_json::json!({"csrfToken": state.csrf_token}).to_string();
    with_content_type(&body, "application/json")
}

async fn proxy_agent(State(state): State<Arc<UiState>>, request: Request) -> Response {
    proxy_to(&state.socket_path, request, "gateway agent").await
}

async fn proxy_proton(State(state): State<Arc<UiState>>, request: Request) -> Response {
    proxy_to(&state.proton_socket_path, request, "Proton broker").await
}

async fn proxy_to(socket_path: &PathBuf, request: Request, service: &str) -> Response {
    let (mut parts, body) = request.into_parts();
    parts.headers.remove(header::AUTHORIZATION);
    let body = match to_bytes(body, 1 << 20).await {
        Ok(body) => body,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    let stream = match UnixStream::connect(socket_path).await {
        Ok(stream) => stream,
        Err(_) => {
            return json_error(StatusCode::BAD_GATEWAY, &format!("{service} unavailable"));
        }
    };
    let (mut sender, connection) = match http1::handshake(TokioIo::new(stream)).await {
        Ok(connection) => connection,
        Err(_) => {
            return json_error(StatusCode::BAD_GATEWAY, &format!("{service} unavailable"));
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut upstream = HyperRequest::builder().method(parts.method).uri(
        parts
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/"),
    );
    if let Some(headers) = upstream.headers_mut() {
        *headers = parts.headers;
        headers.insert(header::HOST, HeaderValue::from_static("agent"));
    }
    let upstream = match upstream.body(Full::new(body)) {
        Ok(request) => request,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid request"),
    };
    let response = match sender.send_request(upstream).await {
        Ok(response) => response,
        Err(_) => {
            return json_error(StatusCode::BAD_GATEWAY, &format!("{service} unavailable"));
        }
    };
    let (parts, body) = response.into_parts();
    let body = match http_body_util::BodyExt::collect(body).await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return json_error(StatusCode::BAD_GATEWAY, &format!("{service} unavailable"));
        }
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = parts.status;
    *response.headers_mut() = parts.headers;
    response
}

async fn authenticate(State(state): State<Arc<UiState>>, request: Request, next: Next) -> Response {
    let client_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|address| address.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    if blocked(&state, &client_ip).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication failures",
        )
            .into_response();
    }
    if !valid_basic_auth(request.headers(), &state.password_hash) {
        record_failure(&state, client_ip).await;
        let mut response = (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Exit Gateway Console\", charset=\"UTF-8\""),
        );
        return response;
    }
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        let provided = request
            .headers()
            .get("X-CSRF-Token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if provided
            .as_bytes()
            .ct_eq(state.csrf_token.as_bytes())
            .unwrap_u8()
            != 1
        {
            return json_error(StatusCode::FORBIDDEN, "invalid CSRF token");
        }
    }
    next.run(request).await
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    response
}

fn valid_basic_auth(headers: &HeaderMap, password_hash: &str) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(credentials) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((username, password)) = credentials.split_once(':') else {
        return false;
    };
    username == "admin" && verify(password, password_hash).unwrap_or(false)
}

async fn blocked(state: &UiState, client_ip: &str) -> bool {
    let cutoff = Instant::now() - Duration::from_secs(5 * 60);
    let mut failures = state.failures.lock().await;
    let recent = failures.entry(client_ip.into()).or_default();
    recent.retain(|failure| *failure > cutoff);
    recent.len() >= 10
}

async fn record_failure(state: &UiState, client_ip: String) {
    state
        .failures
        .lock()
        .await
        .entry(client_ip)
        .or_default()
        .push(Instant::now());
}

fn with_content_type(body: &str, content_type: &'static str) -> Response {
    let mut response = Body::from(body.to_owned()).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn json_error(status: StatusCode, message: &str) -> Response {
    let mut response = (status, serde_json::json!({"error": message}).to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn parse_address(value: &str) -> Result<SocketAddr> {
    let normalized = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.into()
    };
    normalized.parse().context("parse LISTEN_ADDRESS")
}

fn required_environment(name: &str) -> Result<String> {
    let value = env::var(name).unwrap_or_default();
    if value.is_empty() {
        bail!("required environment variable {name} is empty");
    }
    Ok(value)
}

fn environment(name: &str, fallback: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.into())
}
