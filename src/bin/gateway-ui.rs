use std::collections::HashMap;
use std::env;
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{any, get, post};
use axum_server::tls_rustls::RustlsConfig;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request as HyperRequest;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rand::{Rng, RngCore};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tailscale_exit_policy_router::account::{self, Account, AccountStore};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

const INDEX_HTML: &str = include_str!("../../cmd/gateway-ui/static/index.html");
const APP_JS: &str = include_str!("../../cmd/gateway-ui/static/app.js");
const LOGIN_HTML: &str = include_str!("../../cmd/gateway-ui/static/login.html");
const LOGIN_JS: &str = include_str!("../../cmd/gateway-ui/static/login.js");
const STYLES_CSS: &str = include_str!("../../cmd/gateway-ui/static/styles.css");

const SESSION_COOKIE: &str = "tepr_session";
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_SESSIONS: usize = 64;
const FAILURE_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_FAILURES: usize = 10;
const MAX_TRACKED_CLIENTS: usize = 4096;
const RECOVERY_CODE_LIFETIME: Duration = Duration::from_secs(10 * 60);
const RECOVERY_CODE_ATTEMPTS: u32 = 5;
const RECOVERY_REQUEST_INTERVAL: Duration = Duration::from_secs(60);
/// Covers agent mutations that create tunnels and Proton sign-in through the broker.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_BODY_LIMIT: usize = 16 << 20;
const REQUEST_BODY_LIMIT: usize = 1 << 20;
const AUTH_BODY_LIMIT: usize = 4 << 10;

struct UiState {
    socket_path: PathBuf,
    proton_socket_path: PathBuf,
    accounts: AccountStore,
    bcrypt_cost: u32,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
    recovery: Mutex<Recovery>,
}

struct Session {
    csrf_token: Arc<str>,
    /// The password generation the session was opened under.
    generation: [u8; 32],
    created: Instant,
    last_seen: Instant,
}

/// Attached to every authenticated request.
#[derive(Clone)]
struct SessionContext {
    key: [u8; 32],
    csrf_token: Arc<str>,
}

#[derive(Default)]
struct Recovery {
    pending: Option<PendingCode>,
    last_sent: Option<Instant>,
}

struct PendingCode {
    hash: [u8; 32],
    expires: Instant,
    attempts: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("reset-password") {
        return reset_password(&arguments[1..]);
    }
    let accounts = AccountStore::new(account_directory());
    let account = accounts.load()?;
    let state = Arc::new(UiState {
        socket_path: PathBuf::from(environment(
            "CONTROL_SOCKET",
            "/run/tailscale-exit-policy-router/control.sock",
        )),
        proton_socket_path: PathBuf::from(environment(
            "PROTON_BROKER_SOCKET",
            "/run/tailscale-exit-policy-router/proton.sock",
        )),
        accounts,
        bcrypt_cost: account::BCRYPT_COST,
        sessions: Mutex::new(HashMap::new()),
        failures: Mutex::new(HashMap::new()),
        recovery: Mutex::new(Recovery::default()),
    });
    let address = parse_address(&environment("LISTEN_ADDRESS", ":8443"))?;
    let tls = RustlsConfig::from_pem_file(
        required_environment("TLS_CERT_FILE")?,
        required_environment("TLS_KEY_FILE")?,
    )
    .await?;
    info!(%address, username = %account.username, "gateway console ready");
    axum_server::bind_rustls(address, tls)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn account_directory() -> PathBuf {
    PathBuf::from(environment("ACCOUNT_DIRECTORY", "/var/lib/gateway-ui"))
}

/// `gateway-ui reset-password [--username NAME]`, new password on stdin. The
/// last resort when the password is lost and Telegram recovery is unavailable.
fn reset_password(arguments: &[String]) -> Result<()> {
    let username = match arguments {
        [] => None,
        [flag, username] if flag == "--username" => Some(username.clone()),
        _ => bail!("usage: gateway-ui reset-password [--username NAME] < password"),
    };
    let store = AccountStore::new(account_directory());
    let username = username
        .or_else(|| store.load().ok().map(|account| account.username))
        .unwrap_or_else(|| account::DEFAULT_USERNAME.into());
    let mut password = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut password)
        .context("read the new password from stdin")?;
    let password = password.trim_end_matches(['\n', '\r']);
    store.save(&account::new_account(&username, password)?)?;
    eprintln!("Console password for {username} reset; existing sessions have ended.");
    Ok(())
}

fn router(state: Arc<UiState>) -> Router {
    let public = Router::new()
        .route("/login", get(login_page))
        .route("/login.js", get(login_js))
        .route("/styles.css", get(styles_css))
        .route("/auth/login", post(login))
        .route("/auth/recovery/request", post(request_recovery))
        .route("/auth/recovery/reset", post(reset_with_code))
        .with_state(state.clone())
        .layer(from_fn(same_origin_json));
    let protected = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.js", get(app_js))
        .route("/session", get(session))
        .route("/auth/account", get(get_account).put(update_account))
        .route("/auth/logout", post(logout))
        .route("/v1/proton/{*path}", any(proxy_proton))
        .route("/v1/{*path}", any(proxy_agent))
        .with_state(state.clone())
        .layer(from_fn_with_state(state, authenticate));
    public.merge(protected).layer(from_fn(security_headers))
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn login_page() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

async fn app_js() -> Response {
    with_content_type(APP_JS, "text/javascript; charset=utf-8")
}

async fn login_js() -> Response {
    with_content_type(LOGIN_JS, "text/javascript; charset=utf-8")
}

async fn styles_css() -> Response {
    with_content_type(STYLES_CSS, "text/css; charset=utf-8")
}

async fn session(
    State(state): State<Arc<UiState>>,
    Extension(context): Extension<SessionContext>,
) -> Response {
    let username = state
        .accounts
        .load()
        .map(|account| account.username)
        .unwrap_or_default();
    json_response(
        StatusCode::OK,
        json!({"csrfToken": &*context.csrf_token, "username": username}),
    )
}

async fn proxy_agent(State(state): State<Arc<UiState>>, request: Request) -> Response {
    if request.uri().path().starts_with("/v1/internal/") {
        return json_error(StatusCode::NOT_FOUND, "not found");
    }
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
    match exchange(socket_path, parts.method, &path, parts.headers, body.into()).await {
        Err(true) => json_error(
            StatusCode::GATEWAY_TIMEOUT,
            &format!("{service} did not respond in time"),
        ),
        Err(false) => json_error(StatusCode::BAD_GATEWAY, &format!("{service} unavailable")),
        Ok((parts, body)) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = parts.status;
            *response.headers_mut() = parts.headers;
            response
        }
    }
}

/// One HTTP exchange over a Unix socket. `Err(true)` means it timed out.
async fn exchange(
    socket_path: &Path,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(hyper::http::response::Parts, bytes::Bytes), bool> {
    let exchange = async move {
        let stream = UnixStream::connect(socket_path).await.ok()?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.ok()?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut upstream = HyperRequest::builder().method(method).uri(path);
        if let Some(upstream_headers) = upstream.headers_mut() {
            *upstream_headers = headers;
            upstream_headers.insert(header::HOST, HeaderValue::from_static("agent"));
        }
        let response = sender
            .send_request(upstream.body(Full::new(bytes::Bytes::from(body))).ok()?)
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
        Err(_) => Err(true),
        Ok(None) => Err(false),
        Ok(Some(result)) => Ok(result),
    }
}

/// A JSON request to the agent from the console itself.
async fn call_agent(
    state: &UiState,
    method: Method,
    path: &str,
    body: Value,
) -> Option<(StatusCode, Value)> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let (parts, body) = exchange(
        &state.socket_path,
        method,
        path,
        headers,
        body.to_string().into_bytes(),
    )
    .await
    .ok()?;
    Some((
        parts.status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    ))
}

async fn authenticate(State(state): State<Arc<UiState>>, request: Request, next: Next) -> Response {
    if let Some(context) = resume_session(&state, request.headers()).await {
        return authorize(request, next, context).await;
    }
    if request.method() == Method::GET && matches!(request.uri().path(), "/" | "/index.html") {
        return Redirect::to("/login").into_response();
    }
    json_error(StatusCode::UNAUTHORIZED, "authentication required")
}

async fn authorize(mut request: Request, next: Next, context: SessionContext) -> Response {
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
    next.run(request).await
}

/// Sign-in and recovery have no session (and so no CSRF token) yet. Requiring
/// JSON forces a CORS preflight for cross-site callers, and a present Origin
/// must be this site: a form on another site cannot sign a browser in here.
async fn same_origin_json(request: Request, next: Next) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/json") {
        return json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected JSON");
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        let expected = host.map(|host| format!("https://{host}"));
        if origin.to_str().ok() != expected.as_deref() {
            return json_error(StatusCode::FORBIDDEN, "cross-origin request refused");
        }
    }
    next.run(request).await
}

fn client_address(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".into(), |address| address.0.ip().to_string())
}

async fn read_json<T: DeserializeOwned>(request: Request) -> Result<(String, T), Response> {
    let client = client_address(&request);
    let body = to_bytes(request.into_body(), AUTH_BODY_LIMIT)
        .await
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid request body"))?;
    let value = serde_json::from_slice(&body)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid request body"))?;
    Ok((client, value))
}

async fn verify_password(account: &Account, password: String) -> bool {
    let account = account.clone();
    // bcrypt is deliberately slow; keep it off the async worker threads.
    tokio::task::spawn_blocking(move || account.verify(&password))
        .await
        .unwrap_or(false)
}

async fn hash_account(state: &UiState, username: String, password: String) -> Result<Account> {
    let cost = state.bcrypt_cost;
    tokio::task::spawn_blocking(move || account::new_account_with_cost(&username, &password, cost))
        .await
        .context("hash password")?
}

fn too_many_attempts() -> Response {
    json_error(
        StatusCode::TOO_MANY_REQUESTS,
        "too many failed attempts; wait a few minutes",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(State(state): State<Arc<UiState>>, request: Request) -> Response {
    let (client, credentials) = match read_json::<LoginRequest>(request).await {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    if blocked(&state, &client).await {
        return too_many_attempts();
    }
    let account = match state.accounts.load() {
        Ok(account) => account,
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}")),
    };
    let password_valid = verify_password(&account, credentials.password).await;
    let username_valid = credentials
        .username
        .trim()
        .as_bytes()
        .ct_eq(account.username.as_bytes())
        .unwrap_u8()
        == 1;
    if !(password_valid && username_valid) {
        record_failure(&state, client).await;
        return json_error(StatusCode::UNAUTHORIZED, "wrong username or password");
    }
    state.failures.lock().await.remove(&client);
    signed_in(&state, &account).await
}

/// Opens a session for `account` and returns its CSRF token with the cookie.
async fn signed_in(state: &UiState, account: &Account) -> Response {
    let (token, context) = create_session(state, account.generation()).await;
    let mut response = json_response(
        StatusCode::OK,
        json!({"csrfToken": &*context.csrf_token, "username": account.username}),
    );
    if let Ok(cookie) = HeaderValue::from_str(&session_cookie(&token)) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

async fn logout(
    State(state): State<Arc<UiState>>,
    Extension(context): Extension<SessionContext>,
) -> Response {
    state.sessions.lock().await.remove(&context.key);
    let mut response = json_response(StatusCode::OK, json!({"signedOut": true}));
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "tepr_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict",
        ),
    );
    response
}

async fn telegram_recovery_available(state: &UiState) -> bool {
    matches!(
        call_agent(state, Method::GET, "/v1/alerts", Value::Null).await,
        Some((status, body)) if status.is_success() && !body["settings"]["telegram"].is_null()
    )
}

async fn get_account(State(state): State<Arc<UiState>>) -> Response {
    let account = match state.accounts.load() {
        Ok(account) => account,
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}")),
    };
    json_response(
        StatusCode::OK,
        json!({
            "username": account.username,
            "passwordChangedAt": (account.password_changed_at > 0).then_some(account.password_changed_at),
            "recovery": {"telegram": telegram_recovery_available(&state).await},
        }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountUpdate {
    current_password: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    new_password: Option<String>,
}

async fn update_account(
    State(state): State<Arc<UiState>>,
    Extension(context): Extension<SessionContext>,
    request: Request,
) -> Response {
    let (client, update) = match read_json::<AccountUpdate>(request).await {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    if blocked(&state, &client).await {
        return too_many_attempts();
    }
    let current = match state.accounts.load() {
        Ok(account) => account,
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}")),
    };
    // A stolen session must not be enough to take the account over.
    if !verify_password(&current, update.current_password).await {
        record_failure(&state, client).await;
        return json_error(StatusCode::FORBIDDEN, "the current password is wrong");
    }
    let username = update
        .username
        .map(|username| username.trim().to_owned())
        .filter(|username| !username.is_empty())
        .unwrap_or_else(|| current.username.clone());
    let updated = match update.new_password.filter(|password| !password.is_empty()) {
        Some(password) => match hash_account(&state, username, password).await {
            Ok(account) => account,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, &format!("{error:#}")),
        },
        None => {
            if let Err(error) = account::validate_username(&username) {
                return json_error(StatusCode::BAD_REQUEST, &format!("{error:#}"));
            }
            Account {
                username,
                ..current.clone()
            }
        }
    };
    if let Err(error) = state.accounts.save(&updated) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}"));
    }
    let password_changed = updated.generation() != current.generation();
    if password_changed {
        // Every other session ends; this one continues under the new password.
        let mut sessions = state.sessions.lock().await;
        sessions.retain(|key, _| *key == context.key);
        if let Some(session) = sessions.get_mut(&context.key) {
            session.generation = updated.generation();
        }
    }
    info!(username = %updated.username, password_changed, "console account updated");
    json_response(
        StatusCode::OK,
        json!({
            "username": updated.username,
            "passwordChanged": password_changed,
            "passwordChangedAt": (updated.password_changed_at > 0).then_some(updated.password_changed_at),
        }),
    )
}

fn code_hash(code: &str) -> [u8; 32] {
    Sha256::digest(code.as_bytes()).into()
}

async fn request_recovery(State(state): State<Arc<UiState>>, request: Request) -> Response {
    let client = client_address(&request);
    if blocked(&state, &client).await {
        return too_many_attempts();
    }
    let mut recovery = state.recovery.lock().await;
    if recovery
        .last_sent
        .is_some_and(|sent| sent.elapsed() < RECOVERY_REQUEST_INTERVAL)
    {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "a code was sent less than a minute ago; wait before asking again",
        );
    }
    let code = format!("{:08}", rand::rng().random_range(0..100_000_000_u32));
    match call_agent(
        &state,
        Method::POST,
        "/v1/internal/recovery-code",
        json!({"code": code}),
    )
    .await
    {
        Some((status, _)) if status.is_success() => {
            recovery.pending = Some(PendingCode {
                hash: code_hash(&code),
                expires: Instant::now() + RECOVERY_CODE_LIFETIME,
                attempts: 0,
            });
            recovery.last_sent = Some(Instant::now());
            warn!(%client, "console password recovery code sent by Telegram");
            json_response(StatusCode::OK, json!({"sent": true, "channel": "telegram"}))
        }
        Some((StatusCode::CONFLICT, _)) => json_error(
            StatusCode::CONFLICT,
            "Password recovery needs Telegram alerts, which are not set up. Reset the password on the server with scripts/reset-console-password.sh.",
        ),
        Some((_, body)) => json_error(
            StatusCode::BAD_GATEWAY,
            body["error"].as_str().unwrap_or("could not send the code"),
        ),
        None => json_error(StatusCode::BAD_GATEWAY, "gateway agent unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryReset {
    code: String,
    new_password: String,
}

async fn reset_with_code(State(state): State<Arc<UiState>>, request: Request) -> Response {
    let (client, reset) = match read_json::<RecoveryReset>(request).await {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    if blocked(&state, &client).await {
        return too_many_attempts();
    }
    if let Err(error) = account::validate_password(&reset.new_password) {
        return json_error(StatusCode::BAD_REQUEST, &format!("{error:#}"));
    }
    {
        let mut recovery = state.recovery.lock().await;
        let Some(pending) = recovery
            .pending
            .as_mut()
            .filter(|pending| Instant::now() < pending.expires)
        else {
            recovery.pending = None;
            drop(recovery);
            record_failure(&state, client).await;
            return json_error(StatusCode::BAD_REQUEST, "no valid code; ask for a new one");
        };
        let matches = code_hash(reset.code.trim())
            .ct_eq(&pending.hash)
            .unwrap_u8()
            == 1;
        if !matches {
            pending.attempts += 1;
            if pending.attempts >= RECOVERY_CODE_ATTEMPTS {
                recovery.pending = None;
            }
            drop(recovery);
            record_failure(&state, client).await;
            return json_error(StatusCode::BAD_REQUEST, "wrong code");
        }
        // Single use.
        recovery.pending = None;
    }
    let username = match state.accounts.load() {
        Ok(account) => account.username,
        Err(_) => account::DEFAULT_USERNAME.into(),
    };
    let account = match hash_account(&state, username, reset.new_password).await {
        Ok(account) => account,
        Err(error) => return json_error(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    if let Err(error) = state.accounts.save(&account) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}"));
    }
    state.sessions.lock().await.clear();
    state.failures.lock().await.remove(&client);
    warn!(%client, "console password reset with a Telegram recovery code");
    signed_in(&state, &account).await
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
    // A password changed elsewhere (the reset command) ends older sessions.
    let generation = state.accounts.load().ok()?.generation();
    let now = Instant::now();
    let mut sessions = state.sessions.lock().await;
    sessions
        .retain(|_, session| !session_expired(session, now) && session.generation == generation);
    let key = session_key(token);
    let session = sessions.get_mut(&key)?;
    session.last_seen = now;
    Some(SessionContext {
        key,
        csrf_token: session.csrf_token.clone(),
    })
}

async fn create_session(state: &UiState, generation: [u8; 32]) -> (String, SessionContext) {
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
    let key = session_key(&token);
    sessions.insert(
        key,
        Session {
            csrf_token: csrf_token.clone(),
            generation,
            created: now,
            last_seen: now,
        },
    );
    (token, SessionContext { key, csrf_token })
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

fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, value.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn json_error(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({"error": message}))
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
    use tower_service::Service;

    const PASSWORD: &str = "correct horse battery";
    const NEW_PASSWORD: &str = "a different long passphrase";

    struct Fixture {
        state: Arc<UiState>,
        router: Router,
        _directory: tempfile::TempDir,
    }

    fn fixture(socket_path: PathBuf) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let accounts = AccountStore::new(directory.path());
        accounts
            .save(&account::new_account_with_cost("admin", PASSWORD, 4).unwrap())
            .unwrap();
        let state = Arc::new(UiState {
            socket_path,
            proton_socket_path: PathBuf::from("/nonexistent/proton.sock"),
            accounts,
            bcrypt_cost: 4,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            recovery: Mutex::new(Recovery::default()),
        });
        Fixture {
            router: router(state.clone()),
            state,
            _directory: directory,
        }
    }

    async fn send(
        router: &mut Router,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "console.test");
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        let mut request = request.body(body).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
        router.call(request).await.unwrap()
    }

    async fn login(router: &mut Router, username: &str, password: &str) -> Response {
        send(
            router,
            Method::POST,
            "/auth/login",
            &[],
            Some(json!({"username": username, "password": password})),
        )
        .await
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

    async fn json_body(response: Response) -> Value {
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// Signs in and returns (cookie, CSRF token).
    async fn signed_in_session(router: &mut Router, password: &str) -> (String, String) {
        let response = login(router, "admin", password).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = cookie_from(&response);
        let csrf = json_body(response).await["csrfToken"]
            .as_str()
            .unwrap()
            .to_owned();
        (cookie, csrf)
    }

    #[tokio::test]
    async fn anonymous_visitors_get_the_login_page_and_no_browser_prompt() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let page = send(&mut router, Method::GET, "/", &[], None).await;
        assert_eq!(page.status(), StatusCode::SEE_OTHER);
        assert_eq!(page.headers()[header::LOCATION], "/login");
        let api = send(&mut router, Method::GET, "/v1/status", &[], None).await;
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
        assert!(api.headers().get(header::WWW_AUTHENTICATE).is_none());
        for path in ["/login", "/login.js", "/styles.css"] {
            assert_eq!(
                send(&mut router, Method::GET, path, &[], None)
                    .await
                    .status(),
                StatusCode::OK,
                "{path}"
            );
        }
        assert_eq!(
            send(&mut router, Method::GET, "/app.js", &[], None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn login_issues_a_secure_session_cookie() {
        let Fixture {
            mut router,
            state,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let response = login(&mut router, "admin", PASSWORD).await;
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(set_cookie.contains(attribute), "{set_cookie}");
        }
        let cookie = cookie_from(&response);
        let session = send(
            &mut router,
            Method::GET,
            "/session",
            &[("cookie", &cookie)],
            None,
        )
        .await;
        assert_eq!(json_body(session).await["username"], "admin");

        let wrong = login(&mut router, "admin", "wrong password!").await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            login(&mut router, "root", PASSWORD).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(state.failures.lock().await["127.0.0.1"].len(), 2);
    }

    #[tokio::test]
    async fn sign_in_refuses_forms_and_other_origins() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .header(header::HOST, "console.test")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("username=admin&password=x"))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        assert_eq!(
            router.call(request).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let cross = send(
            &mut router,
            Method::POST,
            "/auth/login",
            &[("origin", "https://evil.example")],
            Some(json!({"username": "admin", "password": PASSWORD})),
        )
        .await;
        assert_eq!(cross.status(), StatusCode::FORBIDDEN);
        let same = send(
            &mut router,
            Method::POST,
            "/auth/login",
            &[("origin", "https://console.test")],
            Some(json!({"username": "admin", "password": PASSWORD})),
        )
        .await;
        assert_eq!(same.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mutations_require_the_session_csrf_token() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let (cookie, csrf) = signed_in_session(&mut router, PASSWORD).await;
        let missing = send(
            &mut router,
            Method::POST,
            "/v1/exits",
            &[("cookie", &cookie)],
            None,
        )
        .await;
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);
        let valid = send(
            &mut router,
            Method::POST,
            "/v1/exits",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            None,
        )
        .await;
        // Past authentication and CSRF; the agent socket is absent in this test.
        assert_eq!(valid.status(), StatusCode::BAD_GATEWAY);
        let internal = send(
            &mut router,
            Method::POST,
            "/v1/internal/recovery-code",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            None,
        )
        .await;
        assert_eq!(internal.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn lockout_blocks_passwords_but_not_existing_sessions() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let (cookie, _) = signed_in_session(&mut router, PASSWORD).await;
        for _ in 0..MAX_FAILURES {
            assert_eq!(
                login(&mut router, "admin", "wrong password!")
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            login(&mut router, "admin", PASSWORD).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let session = send(&mut router, Method::GET, "/", &[("cookie", &cookie)], None).await;
        assert_eq!(session.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_ends_the_session() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let (cookie, csrf) = signed_in_session(&mut router, PASSWORD).await;
        let response = send(
            &mut router,
            Method::POST,
            "/auth/logout",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &cookie)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn changing_the_password_needs_the_current_one_and_ends_other_sessions() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let (cookie, csrf) = signed_in_session(&mut router, PASSWORD).await;
        let (other, _) = signed_in_session(&mut router, PASSWORD).await;
        let headers = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];

        let wrong = send(
            &mut router,
            Method::PUT,
            "/auth/account",
            &headers,
            Some(json!({"currentPassword": "not it at all", "newPassword": NEW_PASSWORD})),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        let short = send(
            &mut router,
            Method::PUT,
            "/auth/account",
            &headers,
            Some(json!({"currentPassword": PASSWORD, "newPassword": "short"})),
        )
        .await;
        assert_eq!(short.status(), StatusCode::BAD_REQUEST);

        let changed = send(&mut router, Method::PUT, "/auth/account", &headers, Some(json!({"currentPassword": PASSWORD, "username": "envin", "newPassword": NEW_PASSWORD}))).await;
        assert_eq!(changed.status(), StatusCode::OK);
        let body = json_body(changed).await;
        assert_eq!(body["username"], "envin");
        assert_eq!(body["passwordChanged"], true);

        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &cookie)],
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &other)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&mut router, "envin", PASSWORD).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&mut router, "envin", NEW_PASSWORD).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn renaming_keeps_sessions() {
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let (cookie, csrf) = signed_in_session(&mut router, PASSWORD).await;
        let (other, _) = signed_in_session(&mut router, PASSWORD).await;
        let renamed = send(
            &mut router,
            Method::PUT,
            "/auth/account",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            Some(json!({"currentPassword": PASSWORD, "username": "ops"})),
        )
        .await;
        assert_eq!(json_body(renamed).await["passwordChanged"], false);
        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &other)],
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_reset_from_the_server_ends_every_session() {
        let Fixture {
            mut router,
            state,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let (cookie, _) = signed_in_session(&mut router, PASSWORD).await;
        // What `gateway-ui reset-password` does (in another process).
        state
            .accounts
            .save(&account::new_account_with_cost("admin", NEW_PASSWORD, 4).unwrap())
            .unwrap();
        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &cookie)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&mut router, "admin", NEW_PASSWORD).await.status(),
            StatusCode::OK
        );
    }

    /// A fake agent answering /v1/internal/recovery-code with `status`, which
    /// hands back the code it received.
    fn fake_agent(
        directory: &Path,
        status: &'static str,
    ) -> (PathBuf, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let socket_path = directory.join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = vec![0_u8; 4096];
                let length = stream.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..length]).into_owned();
                if let Some(code) = request.split("\"code\":\"").nth(1) {
                    let _ = sender.send(code[..8].to_owned());
                }
                let body = if status.starts_with("200") {
                    r#"{"sent":true}"#
                } else {
                    r#"{"error":"Telegram is not configured"}"#
                };
                let _ = stream
                    .write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            }
        });
        (socket_path, receiver)
    }

    #[tokio::test]
    async fn telegram_recovery_resets_the_password_with_a_single_use_code() {
        let sockets = tempfile::tempdir().unwrap();
        let (socket_path, mut codes) = fake_agent(sockets.path(), "200 OK");
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(socket_path);
        let (old_session, _) = signed_in_session(&mut router, PASSWORD).await;

        let sent = send(
            &mut router,
            Method::POST,
            "/auth/recovery/request",
            &[],
            Some(json!({})),
        )
        .await;
        assert_eq!(sent.status(), StatusCode::OK);
        let code = codes.recv().await.unwrap();
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        // Asking again right away is refused.
        let again = send(
            &mut router,
            Method::POST,
            "/auth/recovery/request",
            &[],
            Some(json!({})),
        )
        .await;
        assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);

        let wrong_code = if code == "00000000" {
            "11111111"
        } else {
            "00000000"
        };
        let wrong = send(
            &mut router,
            Method::POST,
            "/auth/recovery/reset",
            &[],
            Some(json!({"code": wrong_code, "newPassword": NEW_PASSWORD})),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        let reset = send(
            &mut router,
            Method::POST,
            "/auth/recovery/reset",
            &[],
            Some(json!({"code": code, "newPassword": NEW_PASSWORD})),
        )
        .await;
        assert_eq!(reset.status(), StatusCode::OK);
        let new_session = cookie_from(&reset);
        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &new_session)],
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(
                &mut router,
                Method::GET,
                "/session",
                &[("cookie", &old_session)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&mut router, "admin", NEW_PASSWORD).await.status(),
            StatusCode::OK
        );

        let reused = send(
            &mut router,
            Method::POST,
            "/auth/recovery/reset",
            &[],
            Some(json!({"code": code, "newPassword": "yet another passphrase"})),
        )
        .await;
        assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_recovery_code_dies_after_repeated_wrong_guesses() {
        let Fixture {
            mut router,
            state,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        state.recovery.lock().await.pending = Some(PendingCode {
            hash: code_hash("12345678"),
            expires: Instant::now() + RECOVERY_CODE_LIFETIME,
            attempts: 0,
        });
        for _ in 0..RECOVERY_CODE_ATTEMPTS {
            let wrong = send(
                &mut router,
                Method::POST,
                "/auth/recovery/reset",
                &[],
                Some(json!({"code": "87654321", "newPassword": NEW_PASSWORD})),
            )
            .await;
            assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        }
        let right = send(
            &mut router,
            Method::POST,
            "/auth/recovery/reset",
            &[],
            Some(json!({"code": "12345678", "newPassword": NEW_PASSWORD})),
        )
        .await;
        assert_eq!(right.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(right).await["error"],
            "no valid code; ask for a new one"
        );
    }

    #[tokio::test]
    async fn recovery_without_telegram_points_to_the_server_reset() {
        let sockets = tempfile::tempdir().unwrap();
        let (socket_path, _) = fake_agent(sockets.path(), "409 Conflict");
        let Fixture {
            mut router,
            _directory: _keep,
            ..
        } = fixture(socket_path);
        let response = send(
            &mut router,
            Method::POST,
            "/auth/recovery/request",
            &[],
            Some(json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            json_body(response).await["error"]
                .as_str()
                .unwrap()
                .contains("reset-console-password.sh")
        );
    }

    #[tokio::test]
    async fn expired_sessions_are_rejected() {
        let Fixture {
            state,
            _directory: _keep,
            ..
        } = fixture(PathBuf::from("/nonexistent"));
        let generation = state.accounts.load().unwrap().generation();
        let (token, _) = create_session(&state, generation).await;
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
            .header(header::AUTHORIZATION, "Basic secret")
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
