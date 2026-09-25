//! Notification channels (Telegram and a webhook), their settings, and delivery.
//!
//! Settings are edited in the console and kept in a private file next to the
//! desired state; the Proxmox host watchdog reads the same file. The Telegram
//! bot token is a credential: it is never returned by the API or logged, and
//! HTTP errors are stripped of their URL because the token is part of it.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::alert::Notification;

const DELIVERY_ATTEMPTS: u32 = 4;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
const TELEGRAM_API: &str = "https://api.telegram.org";
const MAX_WEBHOOK_URL: usize = 2048;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Plain-text body with ntfy's Title, Priority, and Tags headers.
    #[default]
    Ntfy,
    /// `{source, key, kind, title, message}`.
    Json,
}

impl std::str::FromStr for Format {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ntfy" => Ok(Self::Ntfy),
            "json" => Ok(Self::Json),
            other => bail!("unknown webhook format {other:?}; use ntfy or json"),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<Telegram>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Telegram {
    pub bot_token: String,
    /// A numeric chat ID (negative for groups) or `@channelname`.
    pub chat_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Webhook {
    pub url: String,
    #[serde(default)]
    pub format: Format,
}

impl Settings {
    pub fn is_empty(&self) -> bool {
        self.telegram.is_none() && self.webhook.is_none()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(telegram) = &self.telegram {
            validate_bot_token(&telegram.bot_token)?;
            validate_chat_id(&telegram.chat_id)?;
        }
        if let Some(webhook) = &self.webhook {
            validate_webhook_url(&webhook.url)?;
        }
        Ok(())
    }
}

impl Telegram {
    /// Identifies the bot without revealing the token: the bot ID is public.
    pub fn token_hint(&self) -> String {
        let bot_id = self.bot_token.split(':').next().unwrap_or_default();
        let tail: String = self
            .bot_token
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("bot {bot_id} (…{tail})")
    }
}

pub fn validate_bot_token(token: &str) -> Result<()> {
    let valid = token.split_once(':').is_some_and(|(id, secret)| {
        !id.is_empty()
            && id.bytes().all(|byte| byte.is_ascii_digit())
            && (30..=64).contains(&secret.len())
            && secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    });
    if !valid {
        bail!("invalid Telegram bot token; it looks like 123456789:AA… (from @BotFather)");
    }
    Ok(())
}

fn validate_chat_id(chat_id: &str) -> Result<()> {
    let numeric = chat_id
        .strip_prefix('-')
        .unwrap_or(chat_id)
        .bytes()
        .all(|byte| byte.is_ascii_digit());
    let channel = chat_id.strip_prefix('@').is_some_and(|name| {
        (5..=32).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    });
    if chat_id.is_empty() || chat_id.len() > 32 || !(numeric || channel) {
        bail!("invalid Telegram chat ID; use a numeric ID or @channelname");
    }
    Ok(())
}

fn validate_webhook_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid webhook URL")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || url.len() > MAX_WEBHOOK_URL
    {
        bail!("the webhook URL must be an http or https URL");
    }
    Ok(())
}

pub struct SettingsStore {
    path: PathBuf,
    current: RwLock<Settings>,
}

impl SettingsStore {
    /// Loads the saved settings; `seed` applies only when nothing was saved yet.
    pub fn open(path: impl Into<PathBuf>, seed: Settings) -> Result<Self> {
        let path = path.into();
        let current = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse alert settings {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => seed,
            Err(error) => return Err(error).context("read alert settings"),
        };
        Ok(Self {
            path,
            current: RwLock::new(current),
        })
    }

    pub fn get(&self) -> Settings {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn replace(&self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let directory = self.path.parent().context("alert settings path")?;
        fs::create_dir_all(directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        std::io::Write::write_all(&mut temporary, &serde_json::to_vec_pretty(&settings)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .context("save alert settings")?;
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = settings;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ChannelResult {
    pub channel: &'static str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Chat {
    pub id: String,
    pub name: String,
    pub kind: String,
}

pub struct Notifier {
    client: reqwest::Client,
    settings: Arc<SettingsStore>,
    source: String,
    telegram_api: String,
}

impl Notifier {
    pub fn new(settings: Arc<SettingsStore>, source: String) -> Result<Self> {
        // A no-op when a provider is already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(DELIVERY_TIMEOUT)
                .build()
                .context("build the notification HTTP client")?,
            settings,
            source,
            telegram_api: TELEGRAM_API.into(),
        })
    }

    pub fn settings(&self) -> &SettingsStore {
        &self.settings
    }

    /// Deliver queued notifications in order, retrying failed channels.
    pub async fn run(self: Arc<Self>, mut queue: mpsc::Receiver<Notification>) {
        while let Some(notification) = queue.recv().await {
            let settings = self.settings.get();
            let mut pending: Vec<&'static str> = channels(&settings);
            for attempt in 1..=DELIVERY_ATTEMPTS {
                let results = self.send_to(&settings, &pending, &notification).await;
                pending = results
                    .iter()
                    .filter(|result| !result.ok)
                    .map(|result| result.channel)
                    .collect();
                for result in results.iter().filter(|result| !result.ok) {
                    warn!(channel = result.channel, error = result.error.as_deref().unwrap_or_default(), attempt, key = %notification.key, "notification delivery failed");
                }
                if pending.is_empty() {
                    break;
                }
                if attempt < DELIVERY_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(5 << attempt)).await;
                }
            }
        }
    }

    /// Send one notification to every configured channel, once.
    pub async fn send(&self, notification: &Notification) -> Vec<ChannelResult> {
        let settings = self.settings.get();
        self.send_to(&settings, &channels(&settings), notification)
            .await
    }

    async fn send_to(
        &self,
        settings: &Settings,
        wanted: &[&'static str],
        notification: &Notification,
    ) -> Vec<ChannelResult> {
        let mut results = Vec::new();
        if let Some(telegram) = settings
            .telegram
            .as_ref()
            .filter(|_| wanted.contains(&"telegram"))
        {
            results.push(result(
                "telegram",
                self.telegram(telegram, notification).await,
            ));
        }
        if let Some(webhook) = settings
            .webhook
            .as_ref()
            .filter(|_| wanted.contains(&"webhook"))
        {
            results.push(result("webhook", self.webhook(webhook, notification).await));
        }
        results
    }

    async fn telegram(&self, telegram: &Telegram, notification: &Notification) -> Result<()> {
        let response = self
            .client
            .post(format!(
                "{}/bot{}/sendMessage",
                self.telegram_api, telegram.bot_token
            ))
            .json(&serde_json::json!({
                "chat_id": telegram.chat_id,
                "text": telegram_text(&self.source, notification),
                "disable_web_page_preview": true,
            }))
            .send()
            .await
            .map_err(redact)?;
        telegram_result(response).await.map(|_| ())
    }

    async fn webhook(&self, webhook: &Webhook, notification: &Notification) -> Result<()> {
        let request = match webhook.format {
            Format::Ntfy => self
                .client
                .post(&webhook.url)
                .header("Title", format!("{}: {}", self.source, notification.title))
                .header(
                    "Priority",
                    if notification.kind == "problem" {
                        "high"
                    } else {
                        "default"
                    },
                )
                .header(
                    "Tags",
                    match notification.kind {
                        "problem" => "warning",
                        "resolved" => "white_check_mark",
                        _ => "information_source",
                    },
                )
                .body(notification.message.clone()),
            Format::Json => self.client.post(&webhook.url).json(&serde_json::json!({
                "source": self.source,
                "key": notification.key,
                "kind": notification.kind,
                "title": notification.title,
                "message": notification.message,
            })),
        };
        let response = request.send().await.map_err(redact)?;
        if !response.status().is_success() {
            bail!("the webhook answered {}", response.status());
        }
        Ok(())
    }

    /// Chats that recently messaged the bot, to find the chat ID to use. Only
    /// works while no other program is polling the same bot.
    pub async fn telegram_chats(&self, bot_token: &str) -> Result<Vec<Chat>> {
        validate_bot_token(bot_token)?;
        let response = self
            .client
            .get(format!("{}/bot{bot_token}/getUpdates", self.telegram_api))
            .send()
            .await
            .map_err(redact)?;
        Ok(parse_chats(&telegram_result(response).await?))
    }
}

pub fn channels(settings: &Settings) -> Vec<&'static str> {
    let mut channels = Vec::new();
    if settings.telegram.is_some() {
        channels.push("telegram");
    }
    if settings.webhook.is_some() {
        channels.push("webhook");
    }
    channels
}

fn result(channel: &'static str, outcome: Result<()>) -> ChannelResult {
    ChannelResult {
        channel,
        ok: outcome.is_ok(),
        error: outcome.err().map(|error| format!("{error:#}")),
    }
}

/// reqwest includes the request URL in errors, and Telegram URLs hold the token.
fn redact(error: reqwest::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", error.without_url())
}

async fn telegram_result(response: reqwest::Response) -> Result<serde_json::Value> {
    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("Telegram answered {status}"))?;
    if body["ok"].as_bool() != Some(true) {
        let description = body["description"].as_str().unwrap_or("request failed");
        bail!("Telegram: {description}");
    }
    Ok(body["result"].clone())
}

fn telegram_text(source: &str, notification: &Notification) -> String {
    let icon = match notification.kind {
        "problem" => "⚠️",
        "resolved" => "✅",
        _ => "ℹ️",
    };
    format!(
        "{icon} {}\n{}\n\n{source}",
        notification.title, notification.message
    )
}

fn parse_chats(updates: &serde_json::Value) -> Vec<Chat> {
    let mut chats: Vec<Chat> = Vec::new();
    for update in updates.as_array().into_iter().flatten() {
        let chat = [
            "message",
            "channel_post",
            "my_chat_member",
            "edited_message",
        ]
        .iter()
        .find_map(|field| update[field]["chat"].as_object());
        let Some(chat) = chat else {
            continue;
        };
        let Some(id) = chat.get("id").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        let name = ["title", "username", "first_name"]
            .iter()
            .find_map(|field| chat.get(*field).and_then(serde_json::Value::as_str))
            .unwrap_or_default();
        let found = Chat {
            id: id.to_string(),
            name: name.to_owned(),
            kind: chat
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        };
        if !chats.iter().any(|existing| existing.id == found.id) {
            chats.push(found);
        }
    }
    chats
}

/// Settings from the environment, used only until settings are saved in the console.
pub fn seed_from_environment() -> Result<Settings> {
    let url = std::env::var("ALERT_WEBHOOK_URL").unwrap_or_default();
    if url.is_empty() {
        return Ok(Settings::default());
    }
    let format = std::env::var("ALERT_WEBHOOK_FORMAT")
        .ok()
        .filter(|format| !format.is_empty())
        .map_or(Ok(Format::Ntfy), |format| format.parse())?;
    let settings = Settings {
        telegram: None,
        webhook: Some(Webhook { url, format }),
    };
    settings.validate()?;
    info!("using the alert webhook from ALERT_WEBHOOK_URL until settings are saved in the console");
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

    fn telegram() -> Telegram {
        Telegram {
            bot_token: TOKEN.into(),
            chat_id: "-1001234567890".into(),
        }
    }

    #[test]
    fn validates_settings() {
        let mut settings = Settings {
            telegram: Some(telegram()),
            webhook: Some(Webhook {
                url: "https://ntfy.sh/a-long-random-topic".into(),
                format: Format::Ntfy,
            }),
        };
        settings.validate().unwrap();
        for chat_id in ["42", "@alerts_channel"] {
            settings.telegram.as_mut().unwrap().chat_id = chat_id.into();
            settings.validate().unwrap();
        }
        for chat_id in ["", "abc", "@ab", "1 2"] {
            settings.telegram.as_mut().unwrap().chat_id = chat_id.into();
            assert!(settings.validate().is_err(), "{chat_id:?}");
        }
        for token in [
            "",
            "123456789",
            "abc:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
            "1:short",
            "1:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDs/w",
        ] {
            assert!(validate_bot_token(token).is_err(), "{token:?}");
        }
        for url in ["ftp://example.com/x", "not a url", "https://"] {
            assert!(validate_webhook_url(url).is_err(), "{url:?}");
        }
    }

    #[test]
    fn token_hint_reveals_only_the_bot_id_and_last_characters() {
        let hint = telegram().token_hint();
        assert_eq!(hint, "bot 123456789 (…Dsaw)");
        assert!(!hint.contains("AAHdq"));
    }

    #[test]
    fn stores_settings_privately_and_reloads_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alerts.json");
        let seed = Settings {
            telegram: None,
            webhook: Some(Webhook {
                url: "https://seed.example/hook".into(),
                format: Format::Json,
            }),
        };
        let store = SettingsStore::open(&path, seed.clone()).unwrap();
        assert_eq!(store.get(), seed);
        let saved = Settings {
            telegram: Some(telegram()),
            webhook: None,
        };
        store.replace(saved.clone()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Once saved, the seed no longer applies.
        assert_eq!(SettingsStore::open(&path, seed).unwrap().get(), saved);
        let invalid = Settings {
            telegram: Some(Telegram {
                bot_token: "nope".into(),
                chat_id: "1".into(),
            }),
            webhook: None,
        };
        assert!(store.replace(invalid).is_err());
        assert_eq!(store.get(), saved);
    }

    #[test]
    fn finds_chats_in_updates() {
        let updates = serde_json::json!([
            {"update_id": 1, "message": {"chat": {"id": 42, "first_name": "Envin", "type": "private"}}},
            {"update_id": 2, "message": {"chat": {"id": 42, "first_name": "Envin", "type": "private"}}},
            {"update_id": 3, "my_chat_member": {"chat": {"id": -100123, "title": "Home alerts", "type": "supergroup"}}},
            {"update_id": 4, "channel_post": {"chat": {"id": -100456, "title": "Ops", "type": "channel"}}},
            {"update_id": 5, "poll": {}}
        ]);
        let chats = parse_chats(&updates);
        assert_eq!(
            chats
                .iter()
                .map(|chat| (chat.id.as_str(), chat.name.as_str(), chat.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("42", "Envin", "private"),
                ("-100123", "Home alerts", "supergroup"),
                ("-100456", "Ops", "channel")
            ]
        );
    }

    #[test]
    fn formats_telegram_messages() {
        let text = telegram_text(
            "gateway",
            &Notification {
                key: "exit:NL".into(),
                title: "Problem: exit NL".into(),
                message: "no traffic passes".into(),
                kind: "problem",
            },
        );
        assert_eq!(text, "⚠️ Problem: exit NL\nno traffic passes\n\ngateway");
    }

    /// A one-shot HTTP server that records the request and answers `body`.
    async fn fake_server(
        status: &'static str,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8192];
            let length = stream.read(&mut request).await.unwrap();
            stream
                .write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                .await
                .unwrap();
            String::from_utf8_lossy(&request[..length]).into_owned()
        });
        (address, handle)
    }

    fn notifier(directory: &std::path::Path, settings: Settings, telegram_api: &str) -> Notifier {
        let store = Arc::new(SettingsStore::open(directory.join("alerts.json"), settings).unwrap());
        let mut notifier = Notifier::new(store, "gateway".into()).unwrap();
        notifier.telegram_api = telegram_api.into();
        notifier
    }

    fn notification() -> Notification {
        Notification {
            key: "test".into(),
            title: "Test".into(),
            message: "hello".into(),
            kind: "info",
        }
    }

    #[tokio::test]
    async fn sends_telegram_messages_and_reports_errors_without_the_token() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings {
            telegram: Some(telegram()),
            webhook: None,
        };
        let (api, request) = fake_server("200 OK", r#"{"ok":true,"result":{}}"#).await;
        let results = notifier(directory.path(), settings.clone(), &api)
            .send(&notification())
            .await;
        assert!(results[0].ok, "{results:?}");
        let request = request.await.unwrap();
        assert!(request.starts_with(&format!("POST /bot{TOKEN}/sendMessage")));
        assert!(request.contains(r#""chat_id":"-1001234567890""#));

        let (api, _) = fake_server(
            "400 Bad Request",
            r#"{"ok":false,"description":"Bad Request: chat not found"}"#,
        )
        .await;
        let results = notifier(directory.path(), settings.clone(), &api)
            .send(&notification())
            .await;
        assert_eq!(
            results[0].error.as_deref(),
            Some("Telegram: Bad Request: chat not found")
        );

        // Connection failures must not echo the URL, which contains the token.
        let results = notifier(directory.path(), settings, "http://127.0.0.1:9")
            .send(&notification())
            .await;
        let error = results[0].error.as_deref().unwrap();
        assert!(
            !error.contains("AAHdq") && !error.contains("123456789"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn sends_ntfy_webhooks() {
        let directory = tempfile::tempdir().unwrap();
        let (url, request) = fake_server("200 OK", "{}").await;
        let settings = Settings {
            telegram: None,
            webhook: Some(Webhook {
                url: format!("{url}/topic"),
                format: Format::Ntfy,
            }),
        };
        let results = notifier(directory.path(), settings, TELEGRAM_API)
            .send(&notification())
            .await;
        assert_eq!(results.len(), 1);
        assert!(results[0].ok, "{results:?}");
        let request = request.await.unwrap().to_lowercase();
        assert!(request.starts_with("post /topic"));
        assert!(request.contains("title: gateway: test"));
        assert!(request.ends_with("hello"));
    }

    #[tokio::test]
    async fn lists_chats_from_the_bot() {
        let directory = tempfile::tempdir().unwrap();
        let (api, request) = fake_server(
            "200 OK",
            r#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":42,"first_name":"Envin","type":"private"}}}]}"#,
        )
        .await;
        let chats = notifier(directory.path(), Settings::default(), &api)
            .telegram_chats(TOKEN)
            .await
            .unwrap();
        assert_eq!(
            chats,
            vec![Chat {
                id: "42".into(),
                name: "Envin".into(),
                kind: "private".into()
            }]
        );
        assert!(
            request
                .await
                .unwrap()
                .starts_with(&format!("GET /bot{TOKEN}/getUpdates"))
        );
    }
}
