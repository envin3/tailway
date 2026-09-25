//! Operator alerts. Conditions are observed repeatedly (every reconcile, every
//! account poll); a notification is sent when a condition has persisted for its
//! grace period, and again when it clears. Delivery is in `notify`.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub const QUEUE_LENGTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Notification {
    pub key: String,
    pub title: String,
    pub message: String,
    /// "problem", "resolved", or "info".
    pub kind: &'static str,
}

/// An active or pending condition, as reported in the status API.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Active {
    pub key: String,
    pub message: String,
    /// Unix time the condition was first observed.
    pub since: u64,
    /// Whether the grace period passed and a notification was sent.
    pub notified: bool,
}

struct Condition {
    message: String,
    first_seen: Instant,
    since: u64,
    notified: bool,
}

pub struct Alerts {
    conditions: Mutex<BTreeMap<String, Condition>>,
    sender: Option<mpsc::Sender<Notification>>,
}

impl Alerts {
    /// Alerts are tracked (and shown in the status API) even without a webhook.
    pub fn new(sender: Option<mpsc::Sender<Notification>>) -> Self {
        Self {
            conditions: Mutex::new(BTreeMap::new()),
            sender,
        }
    }

    fn conditions(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Condition>> {
        self.conditions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record the current state of `key`: `Some(message)` while there is a
    /// problem, `None` when there is none.
    pub fn observe(&self, key: &str, problem: Option<String>, grace: Duration) {
        let notifications = observe(&mut self.conditions(), key, problem, grace, Instant::now());
        for notification in notifications {
            self.send(notification);
        }
    }

    /// Clear every condition whose key starts with `prefix` and is not in `keep`,
    /// for things that disappeared (a removed exit).
    pub fn retain(&self, prefix: &str, keep: &[String]) {
        let stale: Vec<String> = self
            .conditions()
            .keys()
            .filter(|key| key.starts_with(prefix) && !keep.contains(key))
            .cloned()
            .collect();
        for key in stale {
            self.observe(&key, None, Duration::ZERO);
        }
    }

    pub fn info(&self, key: &str, title: &str, message: String) {
        self.send(Notification {
            key: key.into(),
            title: title.into(),
            message,
            kind: "info",
        });
    }

    pub fn active(&self) -> Vec<Active> {
        self.conditions()
            .iter()
            .map(|(key, condition)| Active {
                key: key.clone(),
                message: condition.message.clone(),
                since: condition.since,
                notified: condition.notified,
            })
            .collect()
    }

    fn send(&self, notification: Notification) {
        match notification.kind {
            "problem" => warn!(key = %notification.key, message = %notification.message, "alert"),
            _ => {
                info!(key = %notification.key, message = %notification.message, "alert {}", notification.kind)
            }
        }
        if let Some(sender) = &self.sender
            && sender.try_send(notification).is_err()
        {
            warn!("alert queue full; notification dropped");
        }
    }
}

fn observe(
    conditions: &mut BTreeMap<String, Condition>,
    key: &str,
    problem: Option<String>,
    grace: Duration,
    now: Instant,
) -> Vec<Notification> {
    let mut notifications = Vec::new();
    match problem {
        None => {
            if let Some(condition) = conditions.remove(key)
                && condition.notified
            {
                notifications.push(Notification {
                    key: key.into(),
                    title: format!("Resolved: {}", title(key)),
                    message: format!("Recovered after {}", elapsed(now - condition.first_seen)),
                    kind: "resolved",
                });
            }
        }
        Some(message) => {
            let condition = conditions.entry(key.into()).or_insert_with(|| Condition {
                message: message.clone(),
                first_seen: now,
                since: unix_now(),
                notified: false,
            });
            condition.message = message;
            if !condition.notified && now - condition.first_seen >= grace {
                condition.notified = true;
                notifications.push(Notification {
                    key: key.into(),
                    title: format!("Problem: {}", title(key)),
                    message: condition.message.clone(),
                    kind: "problem",
                });
            }
        }
    }
    notifications
}

fn title(key: &str) -> String {
    match key.split_once(':') {
        Some(("exit", exit)) => format!("exit {exit}"),
        _ => key.replace('-', " "),
    }
}

fn elapsed(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..120 => format!("{seconds}s"),
        120..7200 => format!("{}m", seconds / 60),
        _ => format!("{}h", seconds / 3600),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifies_after_the_grace_period_and_once_on_recovery() {
        let mut conditions = BTreeMap::new();
        let start = Instant::now();
        let grace = Duration::from_secs(60);
        let problem = || Some("tailscaled is not running".to_owned());
        assert!(observe(&mut conditions, "tailscale", problem(), grace, start).is_empty());
        assert!(
            observe(
                &mut conditions,
                "tailscale",
                problem(),
                grace,
                start + Duration::from_secs(30)
            )
            .is_empty()
        );
        let fired = observe(
            &mut conditions,
            "tailscale",
            problem(),
            grace,
            start + Duration::from_secs(61),
        );
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].kind, "problem");
        assert!(
            observe(
                &mut conditions,
                "tailscale",
                problem(),
                grace,
                start + Duration::from_secs(90)
            )
            .is_empty()
        );
        let resolved = observe(
            &mut conditions,
            "tailscale",
            None,
            grace,
            start + Duration::from_secs(300),
        );
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].kind, "resolved");
        assert_eq!(resolved[0].message, "Recovered after 5m");
        assert!(conditions.is_empty());
    }

    #[test]
    fn a_blip_shorter_than_the_grace_period_is_silent() {
        let mut conditions = BTreeMap::new();
        let start = Instant::now();
        let grace = Duration::from_secs(60);
        assert!(observe(&mut conditions, "reconcile", Some("x".into()), grace, start).is_empty());
        assert!(
            observe(
                &mut conditions,
                "reconcile",
                None,
                grace,
                start + Duration::from_secs(30)
            )
            .is_empty()
        );
    }

    #[test]
    fn zero_grace_fires_immediately_with_the_latest_message() {
        let mut conditions = BTreeMap::new();
        let fired = observe(
            &mut conditions,
            "exit:nl-1",
            Some("no traffic passes".into()),
            Duration::ZERO,
            Instant::now(),
        );
        assert_eq!(fired[0].title, "Problem: exit nl-1");
        assert_eq!(fired[0].message, "no traffic passes");
    }

    #[tokio::test]
    async fn retain_resolves_conditions_for_removed_items() {
        let (sender, mut queue) = mpsc::channel(8);
        let alerts = Alerts::new(Some(sender));
        alerts.observe("exit:a", Some("down".into()), Duration::ZERO);
        alerts.observe("exit:b", Some("down".into()), Duration::ZERO);
        alerts.retain("exit:", &["exit:a".into()]);
        let keys: Vec<String> = alerts
            .active()
            .into_iter()
            .map(|active| active.key)
            .collect();
        assert_eq!(keys, vec!["exit:a"]);
        let mut kinds = Vec::new();
        while let Ok(notification) = queue.try_recv() {
            kinds.push((notification.key, notification.kind));
        }
        assert_eq!(
            kinds,
            vec![
                ("exit:a".into(), "problem"),
                ("exit:b".into(), "problem"),
                ("exit:b".into(), "resolved"),
            ]
        );
    }
}
