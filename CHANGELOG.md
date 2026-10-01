# Changelog

All notable changes to Tailway are listed here. Versions follow [Semantic Versioning](https://semver.org). While Tailway is in alpha (`0.x` with an `-alpha` suffix), any release may change behaviour, settings, or stored data without a migration path; read these notes before upgrading.

## [Unreleased]

### Added

- A DNS answer cache in the forwarder, kept separately for each route; repeated lookups are answered in about a millisecond.
- `deploy/proxmox/tailway-tune.sh` and its timer, which turn on UDP GRO forwarding along the gateway's path on a Proxmox host.
- A **Performance** section in the guide, with the recommended host settings.
- **Keep me signed in on this device** at sign-in: the session lasts until 30 days without a visit (at most 180 days) and survives restarts and upgrades.
- **Sign out other browsers** on the account page, which also shows how many other browsers are signed in.
- An event history, kept across restarts in `state/events/`: locations connecting and failing, device route changes with the reason, every settings change with who made it, sign-ins and failed sign-ins with the client address, password changes and resets, and alerts. Shown on the new **Activity** page and on the dashboard, and available at `GET /v1/events`.
- A health registry covering routing, Tailscale, the DNS forwarder, each location, VPN-routed devices, Proton, and the host (disk space, clock synchronisation, connection-tracking table). Shown in a **Health checks** card on the dashboard and at `GET /v1/health`. Low disk space and a nearly full connection table now raise alerts.
- A reason code for each location's status (`statusReason`), including `handshake.no_reply` when a server has sent nothing back at all.
- `GET /healthz` (liveness) and `GET /readyz` (readiness) on the control socket.

### Changed

- IPv6 from devices is refused immediately (a TCP reset) instead of being dropped silently, so apps fall back to IPv4 without delay. `compose.yaml` now turns on IPv6 forwarding in the agent's container; update your copy.
- The agent turns on UDP GRO forwarding on its network interface at startup. The agent image now includes `ethtool`.
- A console session without **Keep me signed in** now ends when the browser closes.
- Logs are plain text without colour codes unless shown on a terminal. `LOG_FORMAT=json` writes JSON lines, and `LOG_LEVEL` sets the detail.
- Tailscale's own messages appear only when they are warnings or errors (`TAILSCALE_LOG=verbose` shows all), without their duplicate timestamps.
- Container logs rotate at 10 MB, five files each.
- Passwords, tokens, private keys, and password hashes print as `<redacted>` wherever they could reach a log.
- The agent container's healthcheck uses `/healthz`, so it restarts only when the agent is stuck, not when a location is down. `compose.yaml` changed; update your copy.

## [0.1.0-alpha.1] - 2026-09-28

First alpha release.

### Added

- Per-device routes for tailnet devices using the gateway as their exit node: a VPN location, direct Internet, local network only, or blocked by default.
- WireGuard configurations from any provider as locations (**Import WireGuard**), with each tunnel's own DNS resolver.
- Proton VPN sign-in, server browsing with load and features, and a separate WireGuard key and automatically renewed certificate per location (unofficial).
- Fail-closed routing: a tunnel that stops passing traffic blocks its devices instead of falling back to the host's connection.
- Health checks from real traffic through each tunnel, with each location's public IP.
- A per-device DNS forwarder: DNS inside the device's own tunnel, a kill switch, and a configurable server for other devices.
- Detection of which devices use the gateway as their exit node, with an alert when a VPN-routed device stops.
- Alerts through Telegram or a webhook (ntfy or JSON), plus an optional watchdog for Proxmox hosts.
- A web console: dashboard, devices, locations, settings, dark mode, and phone layout.
- A console account with sign-up on first run, password changes, and password recovery by email or on the server.
- `--version` on both binaries and `version` in `GET /v1/status`.

[Unreleased]: https://github.com/envin3/tailway/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/envin3/tailway/releases/tag/v0.1.0-alpha.1
