# Changelog

All notable changes to Tailway are listed here. Versions follow [Semantic Versioning](https://semver.org). While Tailway is in alpha (`0.x` with an `-alpha` suffix), any release may change behaviour, settings, or stored data without a migration path; read these notes before upgrading.

## [Unreleased]

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
