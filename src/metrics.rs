//! Numbers about the gateway: the latest values for Prometheus, and a
//! 24-hour, one-point-per-minute history per location for the dashboard.
//!
//! The reconciler records a sample for each location on every pass. The
//! history is saved hourly and at shutdown (`save`), and loaded at start, so
//! a restart keeps the charts.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::domain::ExitStatus;
use crate::health::{Check, Status};

/// Minutes of history kept per location.
const HISTORY_MINUTES: usize = 24 * 60;

/// One pass's view of a location.
#[derive(Clone, Debug, Default)]
pub struct ExitSample {
    pub name: String,
    pub status: ExitStatus,
    pub handshake_age: Option<Duration>,
    /// Totals from the tunnel interface; they restart when it is recreated.
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub probe: Option<Duration>,
}

/// One minute of a location's history.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Point {
    /// Unix time / 60.
    pub minute: u64,
    /// The worst state seen in the minute: 0 failed, 1 connecting,
    /// 2 degraded, 3 healthy.
    pub state: u8,
    /// Probe round trip in milliseconds, if one ran.
    pub probe_ms: Option<u32>,
    /// Average rates over the minute, in bits per second.
    pub received_bps: u64,
    pub sent_bps: u64,
}

#[derive(Default)]
struct Latest {
    sample: ExitSample,
    /// When and at what totals the previous sample was taken, for rates.
    at: u64,
}

#[derive(Default, Deserialize, Serialize)]
struct Saved {
    locations: BTreeMap<String, VecDeque<Point>>,
}

#[derive(Default)]
struct Inner {
    latest: BTreeMap<String, Latest>,
    history: BTreeMap<String, VecDeque<Point>>,
    passes: u64,
    failed_passes: u64,
    last_pass: Duration,
}

pub struct Metrics {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

fn state_value(status: ExitStatus) -> u8 {
    match status {
        ExitStatus::Failed => 0,
        ExitStatus::Pending => 1,
        ExitStatus::Degraded => 2,
        ExitStatus::Healthy => 3,
    }
}

impl Metrics {
    /// Metrics whose history is kept in `path` (none: memory only).
    pub fn new(path: Option<PathBuf>) -> Self {
        let history = path
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<Saved>(&bytes).ok())
            .map(|saved| saved.locations)
            .unwrap_or_default();
        let metrics = Self {
            path,
            inner: Mutex::new(Inner {
                history,
                ..Inner::default()
            }),
        };
        metrics.prune(crate::sessions::now());
        metrics
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn record_pass(&self, duration: Duration, failed: bool) {
        let mut inner = self.inner();
        inner.passes += 1;
        inner.failed_passes += u64::from(failed);
        inner.last_pass = duration;
    }

    /// The locations seen in one pass; others are forgotten (their history
    /// stays until it ages out).
    pub fn record_exits(&self, samples: Vec<ExitSample>, now: u64) {
        let mut inner = self.inner();
        let names: Vec<String> = samples.iter().map(|sample| sample.name.clone()).collect();
        for sample in samples {
            let previous = inner.latest.remove(&sample.name);
            let rate = |now_total: u64, before_total: Option<u64>| match (&previous, before_total) {
                (Some(previous), Some(before)) if now > previous.at && now_total >= before => {
                    (now_total - before) * 8 / (now - previous.at)
                }
                _ => 0,
            };
            let received_bps = rate(
                sample.received_bytes,
                previous
                    .as_ref()
                    .map(|previous| previous.sample.received_bytes),
            );
            let sent_bps = rate(
                sample.sent_bytes,
                previous.as_ref().map(|previous| previous.sample.sent_bytes),
            );
            let point = Point {
                minute: now / 60,
                state: state_value(sample.status),
                probe_ms: sample
                    .probe
                    .map(|probe| u32::try_from(probe.as_millis()).unwrap_or(u32::MAX)),
                received_bps,
                sent_bps,
            };
            let series = inner.history.entry(sample.name.clone()).or_default();
            match series.back_mut() {
                Some(last) if last.minute == point.minute => {
                    last.state = last.state.min(point.state);
                    last.probe_ms = point.probe_ms.or(last.probe_ms);
                    last.received_bps = last.received_bps.max(point.received_bps);
                    last.sent_bps = last.sent_bps.max(point.sent_bps);
                }
                _ => series.push_back(point),
            }
            while series.len() > HISTORY_MINUTES {
                series.pop_front();
            }
            inner
                .latest
                .insert(sample.name.clone(), Latest { sample, at: now });
        }
        inner.latest.retain(|name, _| names.contains(name));
        drop(inner);
        self.prune(now);
    }

    /// Drops points older than a day, and locations left with none.
    fn prune(&self, now: u64) {
        let oldest = (now / 60).saturating_sub(HISTORY_MINUTES as u64);
        self.inner().history.retain(|_, series| {
            while series.front().is_some_and(|point| point.minute < oldest) {
                series.pop_front();
            }
            !series.is_empty()
        });
    }

    pub fn history(&self) -> BTreeMap<String, Vec<Point>> {
        self.inner()
            .history
            .iter()
            .map(|(name, series)| (name.clone(), series.iter().copied().collect()))
            .collect()
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let saved = Saved {
            locations: self.inner().history.clone(),
        };
        let directory = path.parent().context("metrics file has no directory")?;
        fs::create_dir_all(directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        std::io::Write::write_all(&mut temporary, &serde_json::to_vec(&saved)?)?;
        temporary
            .persist(path)
            .context("save the metrics history")?;
        Ok(())
    }

    /// Prometheus text exposition of the latest values.
    pub fn prometheus(&self, extra: &Extra<'_>) -> String {
        let inner = self.inner();
        let mut out = String::new();
        let mut family = |name: &str, kind: &str, help: &str, rows: Vec<(String, f64)>| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (labels, value) in rows {
                let _ = writeln!(out, "{name}{labels} {value}");
            }
        };
        let location = |name: &str| format!("{{location=\"{}\"}}", escape(name));
        let latest: Vec<&ExitSample> = inner.latest.values().map(|latest| &latest.sample).collect();
        family(
            "tailway_info",
            "gauge",
            "Tailway version.",
            vec![(format!("{{version=\"{}\"}}", escape(crate::VERSION)), 1.0)],
        );
        family(
            "tailway_location_up",
            "gauge",
            "Location state: 1 healthy, 0.5 degraded, 0 failed or connecting.",
            latest
                .iter()
                .map(|sample| {
                    let value = match sample.status {
                        ExitStatus::Healthy => 1.0,
                        ExitStatus::Degraded => 0.5,
                        _ => 0.0,
                    };
                    (location(&sample.name), value)
                })
                .collect(),
        );
        family(
            "tailway_location_handshake_age_seconds",
            "gauge",
            "Seconds since the tunnel's last WireGuard handshake.",
            latest
                .iter()
                .filter_map(|sample| {
                    sample
                        .handshake_age
                        .map(|age| (location(&sample.name), age.as_secs() as f64))
                })
                .collect(),
        );
        family(
            "tailway_location_received_bytes",
            "gauge",
            "Bytes received through the tunnel since it was created.",
            latest
                .iter()
                .map(|sample| (location(&sample.name), sample.received_bytes as f64))
                .collect(),
        );
        family(
            "tailway_location_sent_bytes",
            "gauge",
            "Bytes sent through the tunnel since it was created.",
            latest
                .iter()
                .map(|sample| (location(&sample.name), sample.sent_bytes as f64))
                .collect(),
        );
        family(
            "tailway_location_probe_seconds",
            "gauge",
            "Round trip of the latest traffic probe through the tunnel.",
            latest
                .iter()
                .filter_map(|sample| {
                    sample
                        .probe
                        .map(|probe| (location(&sample.name), probe.as_secs_f64()))
                })
                .collect(),
        );
        family(
            "tailway_reconcile_total",
            "counter",
            "Reconcile passes since start.",
            vec![(String::new(), inner.passes as f64)],
        );
        family(
            "tailway_reconcile_failures_total",
            "counter",
            "Reconcile passes that failed since start.",
            vec![(String::new(), inner.failed_passes as f64)],
        );
        family(
            "tailway_reconcile_duration_seconds",
            "gauge",
            "Duration of the latest reconcile pass.",
            vec![(String::new(), inner.last_pass.as_secs_f64())],
        );
        if let Some(dns) = extra.dns {
            let load = |counter: &std::sync::atomic::AtomicU64| {
                counter.load(std::sync::atomic::Ordering::Relaxed) as f64
            };
            family(
                "tailway_dns_queries_total",
                "counter",
                "DNS queries answered by the forwarder.",
                vec![(String::new(), load(&dns.queries))],
            );
            family(
                "tailway_dns_cache_hits_total",
                "counter",
                "DNS queries answered from the cache.",
                vec![(String::new(), load(&dns.cache_hits))],
            );
            family(
                "tailway_dns_failures_total",
                "counter",
                "DNS queries answered SERVFAIL (kill switch, not ready, or no upstream answer).",
                vec![(String::new(), load(&dns.failures))],
            );
        }
        family(
            "tailway_health_check_status",
            "gauge",
            "Health check status: 0 ok, 1 unknown, 2 warning, 3 failed.",
            extra
                .checks
                .iter()
                .map(|check| {
                    let value = match check.status {
                        Status::Ok => 0.0,
                        Status::Unknown => 1.0,
                        Status::Warning => 2.0,
                        Status::Failed => 3.0,
                    };
                    (
                        format!(
                            "{{check=\"{}\",group=\"{}\"}}",
                            escape(&check.id),
                            escape(check.group)
                        ),
                        value,
                    )
                })
                .collect(),
        );
        family(
            "tailway_alerts_active",
            "gauge",
            "Alerts currently raised.",
            vec![(String::new(), extra.alerts_active as f64)],
        );
        out
    }
}

/// Values kept elsewhere that the exposition includes.
pub struct Extra<'a> {
    pub dns: Option<&'a crate::dns::Counters>,
    pub checks: &'a [Check],
    pub alerts_active: usize,
}

/// Escapes a Prometheus label value.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, status: ExitStatus, received: u64) -> ExitSample {
        ExitSample {
            name: name.into(),
            status,
            handshake_age: Some(Duration::from_secs(20)),
            received_bytes: received,
            sent_bytes: 0,
            probe: Some(Duration::from_millis(42)),
        }
    }

    #[test]
    fn keeps_one_point_per_minute_with_rates_and_the_worst_state() {
        let metrics = Metrics::new(None);
        let start = 1_790_000_000 / 60 * 60;
        metrics.record_exits(vec![sample("NL#227", ExitStatus::Healthy, 0)], start);
        metrics.record_exits(
            vec![sample("NL#227", ExitStatus::Degraded, 3_000_000)],
            start + 30,
        );
        metrics.record_exits(
            vec![sample("NL#227", ExitStatus::Healthy, 3_000_000)],
            start + 60,
        );
        let history = metrics.history();
        let points = &history["NL#227"];
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].state, 2, "the worst state in the minute");
        assert_eq!(points[0].received_bps, 800_000, "3 MB in 30 s");
        assert_eq!(points[0].probe_ms, Some(42));
        assert_eq!(points[1].received_bps, 0);
    }

    #[test]
    fn saves_and_restores_the_last_day() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics.json");
        let metrics = Metrics::new(Some(path.clone()));
        let now = crate::sessions::now();
        metrics.record_exits(
            vec![sample("ES#146", ExitStatus::Failed, 0)],
            now - 25 * 3600,
        );
        metrics.record_exits(vec![sample("ES#146", ExitStatus::Healthy, 0)], now);
        metrics.save().unwrap();
        let restored = Metrics::new(Some(path)).history();
        assert_eq!(restored["ES#146"].len(), 1, "older than a day is dropped");
        assert_eq!(restored["ES#146"][0].state, 3);
    }

    #[test]
    fn exposes_prometheus_text() {
        let metrics = Metrics::new(None);
        metrics.record_pass(Duration::from_millis(1500), false);
        metrics.record_exits(vec![sample("a\"b", ExitStatus::Healthy, 10)], 1_000);
        let counters = crate::dns::Counters::default();
        counters
            .queries
            .store(7, std::sync::atomic::Ordering::Relaxed);
        let text = metrics.prometheus(&Extra {
            dns: Some(&counters),
            checks: &[],
            alerts_active: 2,
        });
        for line in [
            "# TYPE tailway_location_up gauge",
            "tailway_location_up{location=\"a\\\"b\"} 1",
            "tailway_location_probe_seconds{location=\"a\\\"b\"} 0.042",
            "tailway_reconcile_duration_seconds 1.5",
            "tailway_dns_queries_total 7",
            "tailway_alerts_active 2",
        ] {
            assert!(
                text.lines().any(|candidate| candidate == line),
                "missing {line}\n{text}"
            );
        }
    }
}
