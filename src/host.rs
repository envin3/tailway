//! Checks of the machine the gateway runs on: free space for its state, a
//! synchronised clock (certificates and WireGuard handshakes depend on it),
//! and room in the connection-tracking table.

use std::path::Path;
use std::time::Duration;

use crate::health::{Alert, Report, Status};

const DISK_WARNING_BYTES: u64 = 200 << 20;
const DISK_FAILED_BYTES: u64 = 50 << 20;
const CONNTRACK_WARNING: f64 = 0.8;
const CONNTRACK_FAILED: f64 = 0.95;

fn report(id: &str, name: &str, status: Status, reason: &str, message: String) -> Report {
    Report {
        id: id.into(),
        group: "host",
        name: name.into(),
        status,
        reason: reason.into(),
        message,
        alert: match id {
            "host:disk" => Alert::on_warning(Duration::from_secs(600)),
            "host:conntrack" => Alert::on_warning(Duration::from_secs(300)),
            _ => None,
        },
    }
}

/// Free space where the gateway keeps its state.
pub fn disk(path: &Path) -> Report {
    let status = |free: u64| {
        if free < DISK_FAILED_BYTES {
            (Status::Failed, "disk.full")
        } else if free < DISK_WARNING_BYTES {
            (Status::Warning, "disk.low")
        } else {
            (Status::Ok, "ok")
        }
    };
    match free_bytes(path) {
        Some(free) => {
            let (status, reason) = status(free);
            report(
                "host:disk",
                "Disk space",
                status,
                reason,
                format!("{} MB free for {}", free >> 20, path.display()),
            )
        }
        None => report(
            "host:disk",
            "Disk space",
            Status::Unknown,
            "disk.unreadable",
            format!("cannot read free space for {}", path.display()),
        ),
    }
}

fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` is written before being read.
    let stats = unsafe {
        if libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) != 0 {
            return None;
        }
        stats.assume_init()
    };
    #[allow(clippy::unnecessary_cast)]
    Some(stats.f_bavail as u64 * stats.f_frsize as u64)
}

/// Whether the kernel clock is synchronised (by NTP on the host).
pub fn clock() -> Report {
    // SAFETY: `modes = 0` only reads the kernel's clock state.
    let (state, status_flags) = unsafe {
        let mut timex = std::mem::zeroed::<libc::timex>();
        let state = libc::adjtimex(&mut timex);
        (state, timex.status)
    };
    let name = "Clock";
    if state < 0 {
        return report(
            "host:clock",
            name,
            Status::Unknown,
            "clock.unreadable",
            "cannot read the clock's synchronisation state".into(),
        );
    }
    if state == libc::TIME_ERROR || status_flags & libc::STA_UNSYNC != 0 {
        report(
            "host:clock",
            name,
            Status::Warning,
            "clock.unsynchronised",
            "the host clock is not synchronised; certificates and VPN handshakes may fail if it drifts. Check NTP on the host.".into(),
        )
    } else {
        report("host:clock", name, Status::Ok, "ok", "synchronised".into())
    }
}

/// How full the connection-tracking table is; when full, new connections fail.
pub fn conntrack(count_path: &Path, max_path: &Path) -> Report {
    let read = |path: &Path| {
        std::fs::read_to_string(path)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    };
    let name = "Connection table";
    let (Some(count), Some(max)) = (read(count_path), read(max_path)) else {
        return report(
            "host:conntrack",
            name,
            Status::Unknown,
            "conntrack.unreadable",
            "cannot read the connection-tracking table size".into(),
        );
    };
    let used = count as f64 / max.max(1) as f64;
    let (status, reason) = if used >= CONNTRACK_FAILED {
        (Status::Failed, "conntrack.full")
    } else if used >= CONNTRACK_WARNING {
        (Status::Warning, "conntrack.high")
    } else {
        (Status::Ok, "ok")
    };
    report(
        "host:conntrack",
        name,
        status,
        reason,
        format!(
            "{count} of {max} tracked connections ({:.0}%)",
            used * 100.0
        ),
    )
}

pub const CONNTRACK_COUNT: &str = "/proc/sys/net/netfilter/nf_conntrack_count";
pub const CONNTRACK_MAX: &str = "/proc/sys/net/netfilter/nf_conntrack_max";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_disk_space_and_rates_the_connection_table() {
        let directory = tempfile::tempdir().unwrap();
        let disk = disk(directory.path());
        assert_ne!(disk.status, Status::Unknown, "{}", disk.message);
        assert!(disk.message.contains("MB free"));
        assert_eq!(
            super::disk(Path::new("/nonexistent/path")).status,
            Status::Unknown
        );

        let file = |value: &str| {
            let path = directory.path().join(value);
            std::fs::write(&path, value).unwrap();
            path
        };
        let max = file("1000");
        for (count, expected) in [
            ("10", Status::Ok),
            ("850", Status::Warning),
            ("990", Status::Failed),
        ] {
            let report = conntrack(&file(count), &max);
            assert_eq!(report.status, expected, "{}", report.message);
        }
        assert_eq!(
            conntrack(Path::new("/nonexistent"), &max).status,
            Status::Unknown
        );
    }

    #[test]
    fn reads_the_clock_state() {
        // Synchronised or not depends on the machine; it must be readable.
        let clock = clock();
        assert_eq!(clock.id, "host:clock");
        assert!(!clock.message.is_empty());
    }
}
