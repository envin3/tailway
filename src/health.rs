//! The health registry: one check per thing that can go wrong, each with a
//! status, a stable reason code, a message, and when it last changed.
//!
//! Checks are reported every reconcile (and every account poll). A check may
//! carry an alert: it is raised once the check has been at least as bad as
//! `Alert::from` for `Alert::grace`, and resolved when it recovers, through
//! [`Alerts`], whose keys are the check IDs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::alert::Alerts;
use crate::events::{Category, Event, EventLog, Severity};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    /// Not known yet, e.g. a tunnel still connecting.
    Unknown,
    Warning,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub struct Alert {
    pub from: Status,
    pub grace: Duration,
}

impl Alert {
    pub const fn on_failure(grace: Duration) -> Option<Self> {
        Some(Self {
            from: Status::Failed,
            grace,
        })
    }

    pub const fn on_warning(grace: Duration) -> Option<Self> {
        Some(Self {
            from: Status::Warning,
            grace,
        })
    }
}

/// What a check found.
pub struct Report {
    /// Stable ID, also the alert key: `tailscale`, `exit:NL#227`, `host:disk`.
    pub id: String,
    /// `gateway`, `locations`, `devices`, `proton`, or `host`.
    pub group: &'static str,
    pub name: String,
    pub status: Status,
    /// Stable code for the finding, e.g. `ok`, `handshake.no_reply`.
    pub reason: String,
    pub message: String,
    pub alert: Option<Alert>,
    /// Record each status change in the event history, so even a short
    /// problem that never reaches an alert leaves a trace.
    pub record: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub id: String,
    pub group: &'static str,
    pub name: String,
    pub status: Status,
    pub reason: String,
    pub message: String,
    /// Unix time the status last changed.
    pub since: u64,
    /// Unix time the check was last OK, if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ok: Option<u64>,
    /// Unix time of the latest report.
    pub checked: u64,
}

pub struct Health {
    checks: Mutex<BTreeMap<String, Check>>,
    alerts: Option<Arc<Alerts>>,
    events: Option<Arc<EventLog>>,
}

impl Health {
    pub fn new(alerts: Option<Arc<Alerts>>) -> Self {
        Self {
            checks: Mutex::new(BTreeMap::new()),
            alerts,
            events: None,
        }
    }

    /// Where checks reported with `record` note their status changes.
    pub fn with_events(mut self, events: Arc<EventLog>) -> Self {
        self.events = Some(events);
        self
    }

    fn checks_mut(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Check>> {
        self.checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn report(&self, report: Report) {
        let now = crate::sessions::now();
        let previous = {
            let mut checks = self.checks_mut();
            let previous = checks.get(&report.id).map(|check| check.status);
            let check = checks.entry(report.id.clone()).or_insert_with(|| Check {
                id: report.id.clone(),
                group: report.group,
                name: report.name.clone(),
                status: report.status,
                reason: String::new(),
                message: String::new(),
                since: now,
                last_ok: None,
                checked: now,
            });
            if check.status != report.status {
                check.since = now;
            }
            check.group = report.group;
            check.name = report.name.clone();
            check.status = report.status;
            check.reason = report.reason.clone();
            check.message = report.message.clone();
            check.checked = now;
            if report.status == Status::Ok {
                check.last_ok = Some(now);
            }
            previous
        };
        if report.record
            && previous != Some(report.status)
            && let Some(events) = &self.events
            && let Some(event) = change_event(previous, &report)
        {
            events.record(event);
        }
        if let (Some(alerts), Some(alert)) = (&self.alerts, report.alert) {
            let problem = (report.status >= alert.from).then_some(report.message);
            alerts.observe(&report.id, problem, alert.grace);
        }
    }

    /// Drops the checks of `group` not in `keep` (a removed location), and
    /// resolves their alerts.
    pub fn retain(&self, group: &str, keep: &[String]) {
        let removed: Vec<String> = {
            let mut checks = self.checks_mut();
            let removed = checks
                .values()
                .filter(|check| check.group == group && !keep.contains(&check.id))
                .map(|check| check.id.clone())
                .collect::<Vec<_>>();
            for id in &removed {
                checks.remove(id);
            }
            removed
        };
        if let Some(alerts) = &self.alerts {
            for id in removed {
                alerts.observe(&id, None, Duration::ZERO);
            }
        }
    }

    pub fn checks(&self) -> Vec<Check> {
        self.checks_mut().values().cloned().collect()
    }

    /// The worst status of any check; `Ok` when there are none.
    pub fn overall(&self) -> Status {
        self.checks_mut()
            .values()
            .map(|check| check.status)
            .max()
            .unwrap_or(Status::Ok)
    }
}

/// The event for a check whose status changed; none for a first report
/// that is fine, or for "unknown".
fn change_event(previous: Option<Status>, report: &Report) -> Option<Event> {
    let (severity, message) = match report.status {
        Status::Unknown => return None,
        Status::Ok if previous.is_none() => return None,
        Status::Ok => (
            Severity::Info,
            format!("{}: back to normal ({})", report.name, report.message),
        ),
        Status::Warning => (
            Severity::Warning,
            format!("{}: {}", report.name, report.message),
        ),
        Status::Failed => (
            Severity::Error,
            format!("{}: {}", report.name, report.message),
        ),
    };
    Some(
        Event::new(severity, Category::Health, "check.changed", message)
            .subject(report.name.clone()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(id: &str, status: Status, alert: Option<Alert>) -> Report {
        Report {
            id: id.into(),
            group: "host",
            name: id.into(),
            status,
            reason: "test".into(),
            message: format!("{id} is {status:?}"),
            alert,
            record: false,
        }
    }

    #[test]
    fn tracks_changes_and_the_worst_status() {
        let health = Health::new(None);
        assert_eq!(health.overall(), Status::Ok);
        health.report(report("host:disk", Status::Ok, None));
        let first = health.checks()[0].clone();
        assert_eq!(first.last_ok, Some(first.since));
        health.report(report("host:disk", Status::Warning, None));
        health.report(report("host:clock", Status::Unknown, None));
        assert_eq!(health.overall(), Status::Warning);
        let disk = health
            .checks()
            .into_iter()
            .find(|check| check.id == "host:disk")
            .unwrap();
        assert_eq!(disk.status, Status::Warning);
        assert_eq!(disk.last_ok, first.last_ok, "last OK is kept");
        health.retain("host", &["host:clock".into()]);
        assert_eq!(health.checks().len(), 1);
    }

    #[test]
    fn drives_alerts_by_the_check_id() {
        let alerts = Arc::new(Alerts::new(None));
        let health = Health::new(Some(alerts.clone()));
        let alert = Alert::on_failure(Duration::ZERO);
        health.report(report("exit:NL#227", Status::Warning, alert));
        assert!(alerts.active().is_empty(), "a warning does not alert here");
        health.report(report("exit:NL#227", Status::Failed, alert));
        let active = alerts.active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].key, "exit:NL#227");
        assert!(active[0].notified);
        health.retain("host", &[]);
        assert!(
            alerts.active().is_empty(),
            "removed checks resolve their alerts"
        );
    }

    #[test]
    fn records_status_changes_of_recorded_checks_only() {
        let directory = tempfile::tempdir().unwrap();
        let events = Arc::new(EventLog::new(directory.path()));
        let health = Health::new(None).with_events(events.clone());
        let recorded = |status| Report {
            record: true,
            ..report("tailscale:coordination", status, None)
        };
        health.report(recorded(Status::Ok));
        health.report(recorded(Status::Ok));
        health.report(recorded(Status::Warning));
        health.report(recorded(Status::Warning));
        health.report(recorded(Status::Ok));
        health.report(report("host:disk", Status::Warning, None));
        let messages: Vec<String> = events
            .query(&crate::events::Query::default())
            .into_iter()
            .map(|event| event.message)
            .collect();
        assert_eq!(
            messages,
            [
                "tailscale:coordination: back to normal (tailscale:coordination is Ok)",
                "tailscale:coordination: tailscale:coordination is Warning",
            ]
        );
    }
}
