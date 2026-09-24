# Proton Policy Router

Experimental IPv4 Tailscale exit-node gateway for Linux container hosts. One Tailscale identity classifies devices by stable node ID and routes each assigned device through a selected Proton WireGuard exit. Unraid is one deployment option.

The gateway agent and management console are implemented in Rust and run as supervised processes in one gateway container. Both binaries share one crate so the persisted schema, API contracts, and policy model remain synchronized.

## Current scope

Implemented:

- Fail-closed `nftables` policy compiler with masked connection marks.
- Explicit WireGuard interfaces, route tables, and `ip rule` entries without `wg-quick` route side effects.
- Static, administrator-approved Proton catalog adapter.
- Stable Tailscale node-ID assignments with atomic versioned state.
- Unix-socket management API and a dropped-privilege TLS console supervised in the gateway container.
- Proton account login, TOTP, and live server discovery through Proton's official Linux API core.
- Multiple concurrent exits, IPv4-only forwarding, per-node direct/local/VPN routing, and stale-resource cleanup.

Not yet release-proven:

- Original Tailscale client source visibility on the target host and Tailscale versions.
- Multiple concurrent Proton tunnels with the account's generated credentials and potentially overlapping tunnel addresses.
- Transactional server replacement and the namespace-sidecar fallback.
- Full audit persistence, egress public-IP verification, upgrade migration, and performance evidence.

These are release gates, not optional enhancements. Follow [docs/spikes/README.md](docs/spikes/README.md) before routing real client traffic.

## Prepare the host

Copy this directory to persistent storage on a Linux Docker Compose host, then run commands from that directory. On Unraid, `/mnt/user/appdata/tailscale-exit-policy-router` is a suitable location.

```sh
cp .env.example .env
mkdir -p config proton-configs proton-broker-state state tls ui-auth
cp config/catalog.example.json config/catalog.json
chgrp "$CONTROL_GID" config proton-configs proton-broker-state state tls ui-auth
chmod 770 proton-broker-state state
chmod 2770 config proton-configs
chmod 750 tls ui-auth
```

Set `HOST_BIND_IP` to a trusted host address and set the shared `CONTROL_GID` in `.env`. Set `UNASSIGNED_POLICY` to `block` (default), `local`, or `direct`; it decides what happens to tailnet nodes that use this exit node without an assignment.

Sockets, the compiled ruleset, and the transient WireGuard configuration live on the Compose-managed `runtime` tmpfs volume, not on disk; they are recreated on every start. Do not replace it with a bind mount: stale files owned by another UID break the capability-restricted agent, and WireGuard private keys would be copied to persistent storage. If the host already runs Tailscale, set `HOST_TAILSCALE_UDP_PORT` to a free UDP port such as `41642`; the container still listens on `41641`. Keep the project on a dedicated Docker bridge and do not attach unrelated containers.

## Import Proton exits

Generate WireGuard configurations from Proton's supported account portal. Put each configuration in `proton-configs/`, assign it to `CONTROL_GID`, and set mode `0640`, then list only its relative filename and public metadata in `config/catalog.json`.

Do not put private keys in the catalog, Compose file, `.env`, this repository, or the Obsidian notes.

## Configure console security

Generate the bcrypt password hash and CSRF secret:

```sh
./scripts/create-ui-secrets.sh
```

Provide a certificate valid for the host's trusted LAN or tailnet name or address:

```text
tls/tls.crt
tls/tls.key
```

Assign both TLS files to `CONTROL_GID` with mode `0640`. The UI child runs as UID `65532` with this group and does not rely on container root to bypass host file modes.

The console refuses to start without TLS, a bcrypt hash, and a 32-byte-or-longer CSRF token. Publish port `8443` only on a trusted LAN or tailnet address and never forward it from the Internet.

## Build and enroll

```sh
docker compose build
docker compose up -d gateway-agent
docker compose exec gateway-agent tailscale up --advertise-exit-node --accept-dns=false --netfilter-mode=off
```

To run an image built elsewhere (for example a test host without the source tree), copy `compose.yaml` and `.env`, load the tagged images with `docker load`, set `IMAGE_TAG`, and start with `docker compose up -d --no-build`.

Approve the exit-node advertisement in the Tailscale admin console. Enrollment state persists in the Compose-managed `tailscale-state` volume; do not keep an auth key in Compose after enrollment. Include this volume in host backups.

Check that the baseline and supervised UI are active:

```sh
docker compose exec gateway-agent nft list table inet tailscale_exit_policy_router
docker compose exec gateway-agent ip rule show
docker compose top gateway-agent
```

Open `https://<HOST_BIND_IP>:8443` and authenticate as `admin` with the password used by the secret generator.

## Proton account discovery

Open **Proton account** in the console and sign in there. The password and TOTP code are sent only over the authenticated TLS console to the capability-free broker; they are never sent to the routing agent or stored by this application. Proton core persists refreshable session data in `proton-broker-state/` with owner-only file permissions, so protect and back up that directory as credential material.

This integration uses Proton's official open-source Linux client internals pinned to `proton-vpn-api-core` 5.6.20. It is not a documented public third-party API and may require compatibility updates when Proton changes the package. TOTP is supported; FIDO2 and additional human-verification challenges are not yet supported.

Live account discovery groups servers by country, shows 12 countries per page, and renders at most 25 servers at a time inside the expanded country. Secure Core, P2P, and Streaming filters can be combined to require every selected feature. Select **Add** to generate a WireGuard profile from the authenticated Proton session and register that server in the routing catalog. Select **Update** later to refresh its endpoint and key material. Generated profiles remain in `proton-configs/` with mode `0640` and are never returned to the browser or routing API.

## Console workflow

1. Open **Nodes** to see every routable Tailscale peer known to the gateway, including offline peers. The gateway node itself is excluded because it cannot route through itself.
2. Select an imported Proton VPN server, **Direct Internet · No VPN**, **Local only · No Internet**, or **Default** (follows `UNASSIGNED_POLICY`) on each node row. Nodes that were removed from the tailnet but still have an assignment are listed as **Removed from tailnet** with a **Clear assignment** button; their assignment is otherwise ignored.
3. Wait for the selected server status to become healthy.
4. Select this single router as the exit node on each client.
5. Run the Phase 0 public-IP, DNS, failure, and packet-capture checks.

The Nodes table reports Tailscale **Gateway activity** from each peer's `Active` status. `Observed` means the gateway currently has an active data path to that peer; `Not observed` means no active path is visible. Tailscale does not expose a client's selected-exit preference in reverse to the gateway, so this is operational evidence rather than proof that the client selected this exit node. Confirm the exact preference on the client with `tailscale status --json` when needed.

The agent reuses one tunnel when multiple nodes choose the same server and removes a tunnel when its final assignment is disabled or moved. While Proton is authenticated, the agent reads `maxConnections` from the broker over its protected Unix socket and rejects creation of a distinct tunnel at that account limit; sharing or replacing an existing tunnel remains allowed. Without authenticated account metadata, the mark space supports up to 255 runtime tunnels. Host resources still apply. **Server selector** and **Active exits** remain available as advanced catalog and tunnel-status views.

`Direct Internet` forwards through the gateway's ordinary Internet connection without Proton. Unassigned nodes follow `UNASSIGNED_POLICY`; the default, `block`, rejects their forwarded traffic so a new or forgotten device never leaves through the home connection by accident. `Local only` blocks public Internet forwarding while preserving direct tailnet connectivity and access to private or link-local IPv4 destinations through the gateway. A selected Proton route remains fail-closed if its tunnel becomes unhealthy.

Exit health comes from WireGuard handshakes, checked on every reconcile. A tunnel is **healthy** when its last handshake is under 180 seconds old, **degraded** up to 300 seconds (traffic stays in the tunnel), and **failed** beyond that or when no handshake arrives within 60 seconds of creation; failed and missing or downed tunnels are recreated automatically. Every peer gets `PersistentKeepalive = 25` if its configuration lacks one, so idle tunnels still handshake. When a node's route changes, its tracked connections are reset so existing flows do not keep using the previous route.

Direct mode inherits the Docker host's egress path. To guarantee that **Direct Internet** means no VPN, disable any host-level VPN or its autoconnect setting; otherwise direct traffic will follow that host VPN even though it does not use a router-managed Proton tunnel.

## Development

```sh
cargo test
cargo build --bins
```

The minimum supported toolchain is Rust 1.85. The agent supports `DRY_RUN=true`; it writes generated policy to the runtime directory without running `ip`, `wg`, or `nft`. Dry-run does not emulate Tailscale peer discovery.

## Security model

The agent runs as root only inside its private network namespace with `NET_ADMIN`, `SETUID`, and `SETGID` plus `/dev/net/tun`. It deliberately lacks `DAC_OVERRIDE` and `FOWNER`: it can only use files it owns or that grant access to `CONTROL_GID`, so the host's file modes still apply to it. `SETUID`/`SETGID` are used only to launch the UI as UID `65532` with `CONTROL_GID`; the UI child does not retain them, and `no-new-privileges` prevents reacquisition. The container has no Docker socket, host network, `SYS_ADMIN`, `SYS_MODULE`, or privileged mode. An unexpected UI exit terminates the container so Compose restarts both processes. Because both processes share one container and mount namespace, the UI no longer has the former container-level filesystem isolation from agent mounts. The Proton account broker remains a separate capability-free container and never returns account session or private WireGuard material through its APIs.

API requests accept logical node, server, and exit IDs only. System commands use direct argument arrays. State writes use `0600` temporary files, `fsync`, optimistic revisions, and atomic rename.

## Known deployment notes

- **`PROTON_CORE_VERSION` pin drift.** `Dockerfile.broker` pins `proton-vpn-api-core` and asserts the installed version matches exactly. Proton's apt repository only retains the current release per suite, so a pin made against an older release (e.g. `5.5.6`) will fail to build once Proton ships a newer version (observed: repo had moved to `5.6.20`). There is no known way to pin an older version through their apt repo; bumping `PROTON_CORE_VERSION` to whatever the repo currently serves is the only option, and the broker's compatibility with that version has not been re-verified beyond "it builds and starts and reaches a healthy state."
- **Runtime files owned by another UID.** If `compose.yaml` is changed to bind-mount the runtime directory from the host, files left there by an earlier run (or re-owned by a recursive `chown`) block the agent: without `DAC_OVERRIDE` it cannot rewrite a `0600` file it does not own, and without `FOWNER` it cannot `chmod` one. Keep the `runtime` tmpfs volume. Granting those capabilities instead would hide the problem and weaken the agent's isolation.
- **`COPY --chown` in `Dockerfile.broker`.** Docker's `COPY` resets file ownership to the current build-stage user (root, by default) regardless of the build context's source ownership. The broker runs as an unprivileged, non-root user (`65533:${CONTROL_GID}`), so without an explicit `--chown=65533:${CONTROL_GID}` on the `COPY proton-broker/proton_broker` line, the broker cannot read its own Python module and fails immediately with `PermissionError`.