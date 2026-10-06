//! Log output for both binaries, and tailscaled's output within it.
//!
//! `LOG_FORMAT=json` writes one JSON object per line, for log collectors;
//! otherwise plain text, coloured only on a terminal. `LOG_LEVEL` takes a
//! level or filter (default `info`). tailscaled is chatty: by default its
//! warnings and errors pass, and so do its connection-state messages (the
//! coordination server, relays, peer paths, network changes), which explain
//! why devices lose the exit node. `TAILSCALE_LOG=verbose` passes everything.

use std::io::IsTerminal;

use tracing::Level;
use tracing_subscriber::EnvFilter;

pub fn init() {
    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal());
    if std::env::var("LOG_FORMAT").is_ok_and(|format| format.eq_ignore_ascii_case("json")) {
        builder.json().flatten_event(true).init();
    } else {
        builder.init();
    }
}

/// tailscaled messages that look alarming but are expected here.
const TAILSCALED_EXPECTED: &[&str] = &[
    // An unprivileged container cannot force socket buffer sizes; the host's
    // defaults apply instead (see the guide's Performance section).
    "failed to force-set UDP",
    // No TPM in a container; tailscaled falls back to plain state.
    "TPM: error opening",
    "[RATELIMIT]",
];

const TAILSCALED_PROBLEMS: &[&str] = &[
    "[unexpected]",
    "[warning]",
    "error",
    "fail",
    "denied",
    "unhealthy",
];

/// tailscaled messages about its connections, kept at info level.
const TAILSCALED_CONNECTION_STATE: &[&str] = &[
    "control:",
    "Switching ipn state",
    "magicsock: derp",
    "magicsock: home is now",
    "magicsock: disco: node",
    "magicsock: endpoints changed",
    "LinkChange",
    "netcheck: report",
    "health(",
];

/// One line of tailscaled output, without its own timestamp, and the level to
/// log it at: warnings and errors, then connection-state messages, stay
/// visible; the rest is debug unless `verbose`.
pub fn tailscaled_line(line: &str, verbose: bool) -> (Level, &str) {
    let text = strip_timestamp(line.trim_end());
    let quiet = if verbose { Level::INFO } else { Level::DEBUG };
    // tailscaled's own verbose levels.
    if text.starts_with("[v1]") || text.starts_with("[v2]") {
        return (quiet, text);
    }
    if TAILSCALED_EXPECTED
        .iter()
        .any(|pattern| text.contains(pattern))
    {
        return (Level::DEBUG, text);
    }
    let lower = text.to_ascii_lowercase();
    if TAILSCALED_PROBLEMS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        return (Level::WARN, text);
    }
    if TAILSCALED_CONNECTION_STATE
        .iter()
        .any(|pattern| text.starts_with(pattern))
    {
        return (Level::INFO, text);
    }
    (quiet, text)
}

/// Logs one line of tailscaled output (see [`tailscaled_line`]).
pub fn log_tailscaled(line: &str, verbose: bool) {
    let (level, text) = tailscaled_line(line, verbose);
    if text.is_empty() {
        return;
    }
    match level {
        Level::WARN => tracing::warn!(component = "tailscaled", "{text}"),
        Level::INFO => tracing::info!(component = "tailscaled", "{text}"),
        _ => tracing::debug!(component = "tailscaled", "{text}"),
    }
}

/// Drops a leading `2026/09/29 17:51:28 `.
fn strip_timestamp(line: &str) -> &str {
    let bytes = line.as_bytes();
    let stamped = bytes.len() >= 20
        && bytes[4] == b'/'
        && bytes[7] == b'/'
        && bytes[10] == b' '
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b' ';
    if stamped { &line[20..] } else { line }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_tailscaled_problems_and_connection_state_and_quiets_the_rest() {
        let (level, text) = tailscaled_line(
            "2026/09/29 17:51:28 magicsock: disco: node [RgMSR] now using 192.168.0.37:41641\n",
            false,
        );
        assert_eq!(level, Level::INFO, "peer paths explain lost exit nodes");
        assert_eq!(
            text,
            "magicsock: disco: node [RgMSR] now using 192.168.0.37:41641"
        );
        for state in [
            "2026/10/05 18:50:01 control: map response long-poll timed out!",
            "2026/10/05 18:50:01 Switching ipn state Running -> Starting",
            "2026/10/05 18:50:01 magicsock: derp-14 connected; connGen=1",
            "2026/10/05 18:50:01 LinkChange: major, rebinding",
            "2026/10/05 18:50:01 health(warnable=not-in-map-poll): ok",
        ] {
            assert_eq!(tailscaled_line(state, false).0, Level::INFO, "{state}");
        }
        for quiet in [
            "2026/09/29 17:51:28 magicsock: rebind",
            "2026/09/29 17:51:28 [v1] control: netmap: delta",
            "2026/09/29 17:51:28 monitor: ip rule deleted",
        ] {
            assert_eq!(tailscaled_line(quiet, false).0, Level::DEBUG, "{quiet}");
        }
        assert_eq!(
            tailscaled_line("2026/09/29 17:51:28 magicsock: rebind", true).0,
            Level::INFO
        );
        for problem in [
            "2026/09/29 17:51:28 control: [unexpected] login failed",
            "2026/09/29 17:51:28 health(warnable=dns): error: DNS unavailable",
            "2026/09/29 17:51:28 netcheck: udp is blocked; fail",
        ] {
            assert_eq!(tailscaled_line(problem, false).0, Level::WARN, "{problem}");
        }
        for expected in [
            "2026/09/29 17:13:13 magicsock: [warning] failed to force-set UDP read buffer size to 7340032: operation not permitted",
            "TPM: error opening: stat /dev/tpmrm0: no such file or directory",
        ] {
            assert_eq!(
                tailscaled_line(expected, false).0,
                Level::DEBUG,
                "{expected}"
            );
        }
    }
}
