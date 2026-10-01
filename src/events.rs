//! The event history: what happened, kept across restarts and upgrades.
//!
//! Only changes are recorded (a location going down, a device's route
//! changing, a setting changed, a sign-in), so it stays small. Events are
//! appended as JSON lines to `events.ndjson`; at `SEGMENT_BYTES` it becomes
//! `events.1.ndjson` and older segments shift up, keeping `SEGMENTS` files.
//! Every event is also written to the log.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const SEGMENT_BYTES: u64 = 1 << 20;
const SEGMENTS: usize = 5;
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 500;
/// Longest message kept; longer ones are cut.
const MAX_MESSAGE: usize = 1000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Locations, routes, alerts: what the gateway did on its own.
    Health,
    /// Settings changed through the console or API.
    Change,
    /// Sign-ins and account security.
    Access,
    /// The gateway starting and stopping.
    System,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// Unix seconds.
    pub time: u64,
    pub severity: Severity,
    pub category: Category,
    /// Machine-readable, e.g. `location.down`, `route.changed`, `console.sign_in`.
    pub kind: String,
    pub message: String,
    /// Who did it: the console user, for changes and sign-ins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Where from: the client's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// What it concerns: a location or device name, for filtering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

impl Event {
    pub fn new(
        severity: Severity,
        category: Category,
        kind: &str,
        message: impl Into<String>,
    ) -> Self {
        let mut message = message.into();
        if message.len() > MAX_MESSAGE {
            let mut end = MAX_MESSAGE;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
            message.push('…');
        }
        Self {
            time: crate::sessions::now(),
            severity,
            category,
            kind: kind.into(),
            message,
            actor: None,
            client: None,
            subject: None,
        }
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn by(mut self, actor: Option<String>, client: Option<String>) -> Self {
        self.actor = actor;
        self.client = client;
        self
    }
}

/// Which events a query returns, newest first.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    /// Only events before this Unix time (for paging back).
    pub before: Option<u64>,
    pub category: Option<Category>,
    /// Only events at least this severe.
    pub severity: Option<Severity>,
    /// Case-insensitive text found in the message, subject, or actor.
    pub search: Option<String>,
    pub limit: Option<usize>,
}

pub struct EventLog {
    directory: PathBuf,
    /// Serializes appends and rotation; holds the current segment's size.
    current: Mutex<Option<u64>>,
}

impl EventLog {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            current: Mutex::new(None),
        }
    }

    fn segment(&self, index: usize) -> PathBuf {
        if index == 0 {
            self.directory.join("events.ndjson")
        } else {
            self.directory.join(format!("events.{index}.ndjson"))
        }
    }

    /// Records `event` and writes it to the log. Never fails: losing an event
    /// must not break what caused it.
    pub fn record(&self, event: Event) {
        let subject = event.subject.as_deref().unwrap_or("");
        let actor = event.actor.as_deref().unwrap_or("");
        match event.severity {
            Severity::Info => info!(kind = %event.kind, subject, actor, "{}", event.message),
            _ => warn!(kind = %event.kind, subject, actor, "{}", event.message),
        }
        if let Err(error) = self.append(&event) {
            warn!(error = %format!("{error:#}"), "cannot write the event history");
        }
    }

    fn append(&self, event: &Event) -> Result<()> {
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let size = match *current {
            Some(size) => size,
            None => {
                fs::create_dir_all(&self.directory).context("create the events directory")?;
                fs::metadata(self.segment(0)).map_or(0, |metadata| metadata.len())
            }
        };
        let size = if size + line.len() as u64 > SEGMENT_BYTES && size > 0 {
            self.rotate()?;
            0
        } else {
            size
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.segment(0))
            .context("open the event history")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if size == 0 {
                fs::set_permissions(self.segment(0), fs::Permissions::from_mode(0o640))?;
            }
        }
        file.write_all(&line)?;
        *current = Some(size + line.len() as u64);
        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        let _ = fs::remove_file(self.segment(SEGMENTS - 1));
        for index in (0..SEGMENTS - 1).rev() {
            let from = self.segment(index);
            if from.exists() {
                fs::rename(&from, self.segment(index + 1)).context("rotate the event history")?;
            }
        }
        Ok(())
    }

    /// Matching events, newest first.
    pub fn query(&self, query: &Query) -> Vec<Event> {
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let search = query.search.as_deref().map(str::to_lowercase);
        let matches = |event: &Event| {
            query.before.is_none_or(|before| event.time < before)
                && query
                    .category
                    .is_none_or(|category| event.category == category)
                && query
                    .severity
                    .is_none_or(|severity| event.severity >= severity)
                && search.as_deref().is_none_or(|search| {
                    [
                        Some(&event.message),
                        event.subject.as_ref(),
                        event.actor.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|text| text.to_lowercase().contains(search))
                })
        };
        // Hold the lock so a rotation cannot move files mid-read.
        let _guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut found = Vec::new();
        for index in 0..SEGMENTS {
            let mut segment: Vec<Event> = read_segment(&self.segment(index))
                .into_iter()
                .filter(|event| matches(event))
                .collect();
            segment.reverse();
            found.extend(segment);
            if found.len() >= limit {
                break;
            }
        }
        found.truncate(limit);
        found
    }
}

/// A segment's events, oldest first; unreadable lines are skipped.
fn read_segment(path: &Path) -> Vec<Event> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(time: u64, severity: Severity, message: &str) -> Event {
        Event {
            time,
            ..Event::new(severity, Category::Health, "test", message)
        }
    }

    #[test]
    fn returns_newest_first_with_filters() {
        let directory = tempfile::tempdir().unwrap();
        let log = EventLog::new(directory.path());
        log.record(event(1, Severity::Info, "NL#227 connected").subject("NL#227"));
        log.record(event(2, Severity::Error, "ES#146 down").subject("ES#146"));
        log.record(
            Event {
                time: 3,
                ..Event::new(Severity::Info, Category::Change, "change", "set a route")
            }
            .by(Some("envin".into()), Some("100.64.0.1".into())),
        );
        let all = log.query(&Query::default());
        assert_eq!(
            all.iter().map(|event| event.time).collect::<Vec<_>>(),
            [3, 2, 1]
        );
        let problems = log.query(&Query {
            severity: Some(Severity::Warning),
            ..Query::default()
        });
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].message, "ES#146 down");
        let changes = log.query(&Query {
            category: Some(Category::Change),
            ..Query::default()
        });
        assert_eq!(changes[0].actor.as_deref(), Some("envin"));
        let searched = log.query(&Query {
            search: Some("nl#".into()),
            ..Query::default()
        });
        assert_eq!(searched.len(), 1);
        let older = log.query(&Query {
            before: Some(3),
            limit: Some(1),
            ..Query::default()
        });
        assert_eq!(older[0].time, 2);
    }

    #[test]
    fn rotates_and_stays_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let log = EventLog::new(directory.path());
        let message = "x".repeat(MAX_MESSAGE);
        let per_segment = SEGMENT_BYTES as usize / (MAX_MESSAGE + 100) + 1;
        let total = per_segment * (SEGMENTS + 2);
        for time in 0..total as u64 {
            log.append(&event(time, Severity::Info, &message)).unwrap();
        }
        let files = fs::read_dir(directory.path()).unwrap().count();
        assert_eq!(files, SEGMENTS);
        let bytes: u64 = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum();
        assert!(bytes <= SEGMENT_BYTES * SEGMENTS as u64);
        // The newest survive, in order, across segments.
        let newest = log.query(&Query {
            limit: Some(MAX_LIMIT),
            ..Query::default()
        });
        assert_eq!(newest[0].time, total as u64 - 1);
        assert!(newest.windows(2).all(|pair| pair[0].time > pair[1].time));
        // A fresh handle continues the current segment rather than starting over.
        let reopened = EventLog::new(directory.path());
        reopened.record(event(total as u64, Severity::Info, "after restart"));
        assert_eq!(
            reopened.query(&Query::default())[0].message,
            "after restart"
        );
    }

    #[test]
    fn long_messages_are_cut() {
        let long = "é".repeat(MAX_MESSAGE);
        let event = Event::new(Severity::Info, Category::Health, "test", long);
        assert!(event.message.len() <= MAX_MESSAGE + '…'.len_utf8());
        assert!(event.message.ends_with('…'));
    }
}
