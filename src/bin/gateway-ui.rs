use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bcrypt::verify;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request as HyperRequest;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::info;

const INDEX_HTML: &str = include_str!("../../cmd/gateway-ui/static/index.html");
const APP_JS: &str = include_str!("../../cmd/gateway-ui/static/app.js");
const STYLES_CSS: &str = include_str!("../../cmd/gateway-ui/static/styles.css");

const SESSION_COOKIE: &str = "tepr_session";
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_SESSIONS: usize = 64;
const FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_FAILURES: usize = 10;
const MAX_TRACKED_CLIENTS: usize = 4096;
/// Covers agent mutations that create tunnels and Proton sign-in through the broker.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_BODY_LIMIT: usize = 16 << 20;
const REQUEST_BODY_LIMIT: usize = 1 << 20;

struct UiState {
    socket_path: PathBuf,
    proton_socket_path: PathBuf,
    password_hash: Arc<str>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

struct Session {
    csrf_token: Arc<str>,
    created: Instant,
    last_seen: Instant,
}

/// Attached to every authenticated request.
#[derive(Clone)]
struct SessionContext {
    csrf_token: Arc<str>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let password_hash = tokio::fs::read_to_string(required_environment("PASSWORD_HASH_FILE")?)
        .await
        .context("read password hash")?;
    let password_hash = password_hash.trim();
    if password_hash.is_empty() {
        bail!("password hash file is empty");
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
        password_hash: Arc::from(password_hash),
        sessions: Mutex::new(HashMap::new()),
        failures: Mutex::new(HashMap::new()),
    });
    let address = parse_address(&environment("LISTEN_ADDRESS", ":8443"))?;
    let tls = RustlsConfig::from_pem_file(
        required_environment("TLS_CERT_FILE")?,
        required_environment("TLS_KEY_FILE")?,
    )
    .await?;
    info!(%address, "gateway console ready");
    axum_server::bind_rustls(address, tls)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn router(state: Arc<UiState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/session", get(session))
        .route("/v1/proton/{*path}", any(proxy_proton))
        .route("/v1/{*path}", any(proxy_agent))
        .with_state(state.clone())
        .layer(from_fn_with_state(state, authenticate))
        .layer(from_fn(security_headers))
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

async fn session(Extension(context): Extension<SessionContext>) -> Response {
    let body = serde_json::json!({"csrfToken": &*context.csrf_token}).to_string();
    with_content_type(&body, "application/json")
}

async fn proxy_agent(State(state): State<Arc<UiState>>, request: Request) -> Response {
    proxy_to(&state.socket_path, request, "gateway agent").await
}

async fn proxy_proton(State(state): State<Arc<UiState>>, request: Request) -> Response {
    proxy_to(&state.proton_socket_path, request, "Proton broker").await
}

async fn proxy_to(socket_path: &Path, request: Request, service: &str) -> Response {
    let (mut parts, body) = request.into_parts();
    // Console credentials and session material never reach the agent or broker.
    parts.headers.remove(header::AUTHORIZATION);
    parts.headers.remove(header::COOKIE);
    parts.headers.remove("x-csrf-token");
    let body = match to_bytes(body, REQUEST_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |value| value.as_str())
        .to_owned();
    let exchange = async move {
        let stream = UnixStream::connect(socket_path).await.ok()?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.ok()?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut upstream = HyperRequest::builder().method(parts.method).uri(path);
        if let Some(headers) = upstream.headers_mut() {
            *headers = parts.headers;
            headers.insert(header::HOST, HeaderValue::from_static("agent"));
        }
        let response = sender
            .send_request(upstream.body(Full::new(body)).ok()?)
            .await
            .ok()?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, UPSTREAM_BODY_LIMIT)
            .collect()
            .await
            .ok()?
            .to_bytes();
        Some((parts, body))
    };
    match tokio::time::timeout(UPSTREAM_TIMEOUT, exchange).await {
        Err(_) => json_error(
            StatusCode::GATEWAY_TIMEOUT,
            &format!("{service} did not respond in time"),
        ),
        Ok(None) => json_error(StatusCode::BAD_GATEWAY, &format!("{service} unavailable")),
        Ok(Some((parts, body))) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = parts.status;
            *response.headers_mut() = parts.headers;
            response
        }
    }
}

async fn authenticate(State(state): State<Arc<UiState>>, request: Request, next: Next) -> Response {
    // A valid session skips bcrypt entirely and is not subject to the lockout, so
    // another client's failed guesses cannot lock out a signed-in administrator.
    if let Some(context) = resume_session(&state, request.headers()).await {
        return authorize(request, next, context, None).await;
    }
    let Some((username, password)) = basic_credentials(request.headers()) else {
        // Browsers probe without credentials first; that is not a failed attempt.
        return unauthorized();
    };
    let client = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".into(), |address| address.0.ip().to_string());
    if blocked(&state, &client).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many authentication failures",
        )
            .into_response();
    }
    let hash = state.password_hash.clone();
    // bcrypt is deliberately slow; keep it off the async worker threads.
    let password_valid =
        tokio::task::spawn_blocking(move || verify(password, &hash).unwrap_or(false))
            .await
            .unwrap_or(false);
    if !(password_valid && username == "admin") {
        record_failure(&state, client).await;
        return unauthorized();
    }
    state.failures.lock().await.remove(&client);
    let (token, context) = create_session(&state).await;
    authorize(request, next, context, Some(token)).await
}

async fn authorize(
    mut request: Request,
    next: Next,
    context: SessionContext,
    new_session_token: Option<String>,
) -> Response {
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
            .ct_eq(context.csrf_token.as_bytes())
            .unwrap_u8()
            != 1
        {
            return json_error(StatusCode::FORBIDDEN, "invalid CSRF token");
        }
    }
    request.extensions_mut().insert(context);
    let mut response = next.run(request).await;
    if let Some(token) = new_session_token
        && let Ok(cookie) = HeaderValue::from_str(&session_cookie(&token))
    {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
        SESSION_LIFETIME.as_secs()
    )
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(SESSION_COOKIE)
                .and_then(|rest| rest.strip_prefix('='))
        })
}

/// Sessions are looked up by token hash so the lookup does not leak token prefixes.
fn session_key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_hex() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn session_expired(session: &Session, now: Instant) -> bool {
    now.duration_since(session.created) > SESSION_LIFETIME
        || now.duration_since(session.last_seen) > SESSION_IDLE_TIMEOUT
}

async fn resume_session(state: &UiState, headers: &HeaderMap) -> Option<SessionContext> {
    let token = session_token(headers)?;
    let now = Instant::now();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| !session_expired(session, now));
    let session = sessions.get_mut(&session_key(token))?;
    session.last_seen = now;
    Some(SessionContext {
        csrf_token: session.csrf_token.clone(),
    })
}

async fn create_session(state: &UiState) -> (String, SessionContext) {
    let token = random_hex();
    let csrf_token: Arc<str> = Arc::from(random_hex());
    let now = Instant::now();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| !session_expired(session, now));
    while sessions.len() >= MAX_SESSIONS {
        let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, session)| session.last_seen)
            .map(|(key, _)| *key)
        else {
            break;
        };
        sessions.remove(&oldest);
    }
    sessions.insert(
        session_key(&token),
        Session {
            csrf_token: csrf_token.clone(),
            created: now,
            last_seen: now,
        },
    );
    (token, SessionContext { csrf_token })
}

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"Exit Gateway Console\", charset=\"UTF-8\""),
    );
    response
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

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let decoded = STANDARD.decode(value.strip_prefix("Basic ")?).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let (username, password) = credentials.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

/// Failures newer than this still count. `None` shortly after boot, when the
/// monotonic clock is younger than the window and every failure is recent.
fn failure_cutoff(now: Instant) -> Option<Instant> {
    now.checked_sub(FAILURE_WINDOW)
}

fn recent_failure(failure: Instant, cutoff: Option<Instant>) -> bool {
    cutoff.is_none_or(|cutoff| failure > cutoff)
}

async fn blocked(state: &UiState, client: &str) -> bool {
    let cutoff = failure_cutoff(Instant::now());
    let mut failures = state.failures.lock().await;
    let Some(recent) = failures.get_mut(client) else {
        return false;
    };
    recent.retain(|failure| recent_failure(*failure, cutoff));
    if recent.is_empty() {
        failures.remove(client);
        return false;
    }
    recent.len() >= MAX_FAILURES
}

async fn record_failure(state: &UiState, client: String) {
    let now = Instant::now();
    let cutoff = failure_cutoff(now);
    let mut failures = state.failures.lock().await;
    failures.retain(|_, recent| {
        recent.retain(|failure| recent_failure(*failure, cutoff));
        !recent.is_empty()
    });
    if failures.len() >= MAX_TRACKED_CLIENTS && !failures.contains_key(&client) {
        let oldest = failures
            .iter()
            .min_by_key(|(_, recent)| recent.last().copied())
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            failures.remove(&oldest);
        }
    }
    failures.entry(client).or_default().push(now);
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ConnectInfo;
    use tower_service::Service;

    const PASSWORD: &str = "correct horse";

    fn state(socket_path: PathBuf) -> Arc<UiState> {
        Arc::new(UiState {
            socket_path,
            proton_socket_path: PathBuf::from("/nonexistent/proton.sock"),
            password_hash: Arc::from(bcrypt::hash(PASSWORD, 4).unwrap()),
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        })
    }

    fn basic(password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("admin:{password}")))
    }

    async fn send(
        router: &mut Router,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
        router.call(request).await.unwrap()
    }

    fn cookie_from(response: &Response) -> String {
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        set_cookie.split(';').next().unwrap().to_owned()
    }

    async fn csrf_from(response: Response) -> String {
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["csrfToken"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn password_login_issues_a_session_cookie() {
        let mut router = router(state(PathBuf::from("/nonexistent")));
        let response = send(
            &mut router,
            Method::GET,
            "/session",
            &[("authorization", &basic(PASSWORD))],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(set_cookie.contains(attribute), "{set_cookie}");
        }
        let cookie = cookie_from(&response);
        // The session alone authenticates later requests; no password is needed.
        let resumed = send(&mut router, Method::GET, "/session", &[("cookie", &cookie)]).await;
        assert_eq!(resumed.status(), StatusCode::OK);
        assert!(resumed.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn mutations_require_the_session_csrf_token() {
        let mut router = router(state(PathBuf::from("/nonexistent")));
        let login = send(
            &mut router,
            Method::GET,
            "/session",
            &[("authorization", &basic(PASSWORD))],
        )
        .await;
        let cookie = cookie_from(&login);
        let csrf = csrf_from(login).await;

        let missing = send(
            &mut router,
            Method::POST,
            "/v1/exits",
            &[("cookie", &cookie)],
        )
        .await;
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);

        let valid = send(
            &mut router,
            Method::POST,
            "/v1/exits",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
        )
        .await;
        // Past authentication and CSRF; the agent socket is absent in this test.
        assert_eq!(valid.status(), StatusCode::BAD_GATEWAY);

        // A password alone cannot mutate: a fresh session's token is unknown to
        // the caller, which is what stops cross-site requests riding on cached
        // Basic credentials.
        let password_only = send(
            &mut router,
            Method::POST,
            "/v1/exits",
            &[("authorization", &basic(PASSWORD)), ("x-csrf-token", &csrf)],
        )
        .await;
        assert_eq!(password_only.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn requests_without_credentials_do_not_count_as_failures() {
        let state = state(PathBuf::from("/nonexistent"));
        let mut router = router(state.clone());
        for _ in 0..(MAX_FAILURES * 2) {
            let response = send(&mut router, Method::GET, "/", &[]).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert!(state.failures.lock().await.is_empty());
        let response = send(
            &mut router,
            Method::GET,
            "/",
            &[("authorization", &basic(PASSWORD))],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn lockout_blocks_passwords_but_not_existing_sessions() {
        let mut router = router(state(PathBuf::from("/nonexistent")));
        let login = send(
            &mut router,
            Method::GET,
            "/",
            &[("authorization", &basic(PASSWORD))],
        )
        .await;
        let cookie = cookie_from(&login);
        for _ in 0..MAX_FAILURES {
            let response = send(
                &mut router,
                Method::GET,
                "/",
                &[("authorization", &basic("wrong"))],
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let blocked = send(
            &mut router,
            Method::GET,
            "/",
            &[("authorization", &basic(PASSWORD))],
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        let session = send(&mut router, Method::GET, "/", &[("cookie", &cookie)]).await;
        assert_eq!(session.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn expired_sessions_are_rejected() {
        let state = state(PathBuf::from("/nonexistent"));
        let (token, _) = create_session(&state).await;
        for session in state.sessions.lock().await.values_mut() {
            session.last_seen -= SESSION_IDLE_TIMEOUT + Duration::from_secs(1);
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}")).unwrap(),
        );
        assert!(resume_session(&state, &headers).await.is_none());
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn proxy_strips_credentials_and_times_out() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 4096];
            let length = stream.read(&mut buffer).await.unwrap();
            let _ = sender.send(String::from_utf8_lossy(&buffer[..length]).to_lowercase());
            // Never answer, forcing the proxy timeout.
            tokio::time::sleep(UPSTREAM_TIMEOUT * 2).await;
        });
        tokio::time::pause();
        let request = Request::builder()
            .uri("/v1/status")
            .header(header::AUTHORIZATION, basic(PASSWORD))
            .header(header::COOKIE, format!("{SESSION_COOKIE}=secret"))
            .header("x-csrf-token", "token")
            .body(Body::empty())
            .unwrap();
        let response = proxy_to(&socket_path, request, "gateway agent").await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let forwarded = receiver.await.unwrap();
        assert!(forwarded.starts_with("get /v1/status"));
        for secret in ["authorization", "tepr_session", "x-csrf-token"] {
            assert!(
                !forwarded.contains(secret),
                "{secret} forwarded:\n{forwarded}"
            );
        }
        upstream.abort();
    }

    #[test]
    fn parses_the_session_cookie_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; tepr_session=abc123; other=1"),
        );
        assert_eq!(session_token(&headers), Some("abc123"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("tepr_session_x=nope"),
        );
        assert_eq!(session_token(&headers), None);
    }
}
