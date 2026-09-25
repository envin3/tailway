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

Sockets, the compiled ruleset, and the transient WireGuard configuration live on the Compose-managed `runtime` tmpfs volume, not on disk; they are recreated on every start. Do not replace it with a bind mount: stale files owned by another UID break the capability-restricted agent, and WireGuard private keys would be copied to persistent storage. If the host already runs Tailscale, set `HOST_TAILSCALE_UDP_PORT` to a free UDP port such as `41642`. The container's `tailscaled` listens on the same port, because Tailscale advertises its own listen port to peers; with the two ports different, direct connections fail and traffic falls back to relays. Keep the project on a dedicated Docker bridge and do not attach unrelated containers.

## Import Proton exits

Generate WireGuard configurations from Proton's supported account portal. Put each configuration in `proton-configs/`, assign it to `CONTROL_GID`, and set mode `0640`, then list only its relative filename and public metadata in `config/catalog.json`.

Do not put private keys in the catalog, Compose file, `.env`, this repository, or the Obsidian notes.

## Configure console security

Generate the bcrypt password hash:

```sh
./scripts/create-ui-secrets.sh
```

Provide a certificate valid for the host's trusted LAN or tailnet name or address:

```text
tls/tls.crt
tls/tls.key
```

Assign both TLS files to `CONTROL_GID` with mode `0640`. The UI child runs as UID `65532` with this group and does not rely on container root to bypass host file modes.

The console refuses to start without TLS and a bcrypt hash. Publish port `8443` only on a trusted LAN or tailnet address and never forward it from the Internet.

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

The browser's password prompt (HTTP Basic) is only the login step. A successful login issues an `HttpOnly`, `Secure`, `SameSite=Strict` session cookie that expires after 30 minutes idle or 12 hours, so bcrypt runs once per session rather than on every request. Each session has its own CSRF token, fetched from `/session`; changes require both the session cookie and that token, so cached Basic credentials alone cannot change routing. Ten wrong passwords from one client address within five minutes block further password attempts from that address for the rest of the window; requests without credentials do not count, and existing sessions keep working. Behind a reverse proxy such as `tailscale serve`, every client shares the proxy's address for this limit. Requests to the agent and broker time out after 30 seconds.

## Proton account discovery

Open **Proton account** in the console and sign in there. The password and TOTP code are sent only over the authenticated TLS console to the capability-free broker; they are never sent to the routing agent or stored by this application. Proton core persists refreshable session data in `proton-broker-state/` with owner-only file permissions, so protect and back up that directory as credential material.

This integration uses Proton's official open-source Linux client internals pinned to `proton-vpn-api-core` 5.6.20. It is not a documented public third-party API and may require compatibility updates when Proton changes the package. TOTP is supported; FIDO2 and additional human-verification challenges are not yet supported.

Live account discovery groups servers by country, shows 12 countries per page, and renders at most 25 servers at a time inside the expanded country. Secure Core, P2P, and Streaming filters can be combined to require every selected feature. Select **Add** to generate a WireGuard profile from the authenticated Proton session and register that server in the routing catalog. Select **Update** later to refresh its endpoint and key material. Generated profiles remain in `proton-configs/` with mode `0640` and are never returned to the browser or routing API.

Each imported exit gets its **own WireGuard key**. Proton tracks one active server per key: when several tunnels share a key, the servers keep taking the session from each other and every tunnel drops traffic for 10–20 seconds at a time. The broker generates a key per exit and requests a certificate for it through the signed-in session. This is the same `POST /vpn/v1/certificate` call the official client makes for its own key. Keys and certificate times are kept in `proton-broker-state/exit-keys.json` (mode 0600).

Certificates are valid for about a week. **With an expired certificate, Proton servers still complete WireGuard handshakes but stop forwarding data.** Every five minutes (and at startup) the broker:

- renews each certificate once Proton's refresh time has passed; the profile and tunnel do not change;
- rewrites any profile that does not carry its exit's key, for example one imported before per-exit keys or restored from a backup.

A new sign-in renews every certificate but keeps the keys. The broker also runs Proton's own background refresher, which keeps the server list current. The **Proton account** page shows how long the certificate closest to expiry remains valid.

The official client also opens a TLS session to each server's local agent (`10.2.0.1:65432`) through the tunnel to read connection state (for example *jailed* when a certificate has expired) and to set features such as NetShield and the exit IP. Traffic flows without it, so this router does not use it yet.

## Console workflow

1. Open **Nodes** to see every routable Tailscale peer known to the gateway, including offline peers. The gateway node itself is excluded because it cannot route through itself.
2. Select an imported Proton VPN server, **Direct Internet · No VPN**, **Local only · No Internet**, or **Default** (follows `UNASSIGNED_POLICY`) on each node row. Nodes that were removed from the tailnet but still have an assignment are listed as **Removed from tailnet** with a **Clear assignment** button; their assignment is otherwise ignored.
3. Wait for the selected server status to become healthy.
4. Select this single router as the exit node on each client.
5. Run the Phase 0 public-IP, DNS, failure, and packet-capture checks.

The Nodes table reports Tailscale **Gateway activity** from each peer's `Active` status. `Observed` means the gateway currently has an active data path to that peer; `Not observed` means no active path is visible. Tailscale does not expose a client's selected-exit preference in reverse to the gateway, so this is operational evidence rather than proof that the client selected this exit node. Confirm the exact preference on the client with `tailscale status --json` when needed.

The agent reuses one tunnel when multiple nodes choose the same server and removes a tunnel when its final assignment is disabled or moved. While Proton is authenticated, the agent reads `maxConnections` from the broker over its protected Unix socket and rejects creation of a distinct tunnel at that account limit; sharing or replacing an existing tunnel remains allowed. Without authenticated account metadata, the mark space supports up to 255 runtime tunnels. Host resources still apply. **Server selector** and **Active exits** remain available as advanced catalog and tunnel-status views.

`Direct Internet` forwards through the gateway's ordinary Internet connection without Proton. Unassigned nodes follow `UNASSIGNED_POLICY`; the default, `block`, rejects their forwarded traffic so a new or forgotten device never leaves through the home connection by accident. `Local only` blocks public Internet forwarding while preserving direct tailnet connectivity and access to private or link-local IPv4 destinations through the gateway. A selected Proton route remains fail-closed if its tunnel becomes unhealthy.

Each tunnel's routing table also carries a lowest-priority `unreachable` default route, so if the tunnel interface goes down or disappears, traffic and the gateway's own DNS queries for that exit fail instead of falling through to the home connection. Exit health is checked on every reconcile, in two layers:

- **Handshakes.** A tunnel is **healthy** when its last handshake is under 180 seconds old, **degraded** up to 300 seconds (traffic stays in the tunnel), and **failed** beyond that or when no handshake arrives within 60 seconds of creation. Failed tunnels, and tunnels that are missing or down, are recreated automatically.
- **Traffic.** A handshake proves only the control plane: Proton completes handshakes for a key it no longer forwards traffic for. So every tunnel with a good handshake also gets real packets, sent with the tunnel's firewall mark: a public-address lookup (OpenDNS `myip.opendns.com`, falling back to Cloudflare `whoami.cloudflare`) and a query to Proton's in-tunnel resolver 10.2.0.1.
  - A successful lookup shows the exit's **public IP** in the console.
  - One failed lookup marks the exit degraded. Two in a row mark it **failed**, which blocks its devices, and the tunnel is recreated then and every ten failures after that.
  - Two unanswered resolver queries in a row mark the exit degraded. Every peer gets `PersistentKeepalive = 25` if its configuration lacks one, so idle tunnels still handshake. When a node's route changes, its tracked connections are reset so existing flows do not keep using the previous route.

Direct mode inherits the Docker host's egress path. To guarantee that **Direct Internet** means no VPN, disable any host-level VPN or its autoconnect setting; otherwise direct traffic will follow that host VPN even though it does not use a router-managed Proton tunnel.

## DNS

By default Tailscale resolves an exit node client's lookups on the exit node itself: the gateway's own `tailscaled` answers them through the gateway's normal connection, so a VPN-routed device leaks every hostname it looks up to the home ISP. The router cannot see which device asked, because those lookups are not forwarded packets.

The agent therefore includes a per-device DNS forwarder. Point the tailnet at it in the Tailscale admin console under **DNS**:

1. Add the gateway's tailnet IPv4 address as a nameserver, then your home router (or another resolver) as a second one, and enable **Override DNS servers**.
2. Keep **Allow local network access** off on devices that use this exit node.

MagicDNS keeps working: each device still answers tailnet names itself and forwards only other names. The forwarder sees which device asked and resolves accordingly:

| Device | DNS |
|---|---|
| Routed to a Proton exit | `10.2.0.1` through that device's own tunnel, answered by its own Proton server |
| Proton exit down, kill switch on (default) | `SERVFAIL`; nothing resolves |
| Proton exit down, kill switch off | the device's DNS server over the gateway's own connection |
| Direct, Local only, unassigned, or not using this exit node | the device's DNS server, default `DNS_DEFAULT_SERVER` (`9.9.9.9`) |

Set the kill switch and DNS server per device in the **DNS** column of **Nodes**. `DNS_KILL_SWITCH_DEFAULT` sets the default kill switch; `DNS_FORWARDER=false` disables the forwarder.

The nftables table redirects TCP and UDP port 53 addressed to the gateway itself on `tailscale0` to the forwarder on port 5353, so the agent needs no extra capability; DNS forwarded to other resolvers is routed like any other traffic. Only tailnet addresses (`100.64.0.0/10`) are answered. Until the gateway's own Tailscale is running with the tailnet's device list, and whenever it is not (for example logged out), every lookup gets `SERVFAIL`: without the device list a Proton device would look unknown and be sent to the default server over the home connection. After a restart the agent reconciles every two seconds until Tailscale is running, so DNS normally returns within seconds.

If the gateway is down, Tailscale uses the second nameserver. Devices using this exit node cannot reach it, because their traffic still goes to the unavailable exit node, so they get no DNS at all; other devices keep resolving. Tailscale may occasionally use the second nameserver even while the gateway is up.

## Alerts

Set `ALERT_WEBHOOK_URL` in `.env` to receive notifications. The value is either an [ntfy](https://ntfy.sh) topic URL (the default `ALERT_WEBHOOK_FORMAT=ntfy` sends a plain-text body with `Title`, `Priority`, and `Tags` headers) or any webhook that accepts `ALERT_WEBHOOK_FORMAT=json` (`{source, key, kind, title, message}`). The agent sends a notification when a problem outlasts its grace period, and another when it clears:

| Condition | Grace |
| --- | --- |
| An exit is failed (its devices are blocked) | none (already debounced by the health checks) |
| Reconciliation keeps failing | 90 s |
| Tailscale on the gateway is not running | 3 min |
| The Proton session is signed out, or the broker is unreachable | 10 min (polled every 5 min) |
| Certificate renewal is not running, or the certificate expires within 24 h | none |

The agent also sends an info message whenever it starts, so restarts are visible. Without a webhook, alerts are still logged. The console shows the notified ones in its banner and health indicator, and `GET /v1/status` lists all current conditions under `alerts`.

The agent cannot report its own absence. On a Proxmox host, `deploy/proxmox/` has a watchdog that runs every two minutes. It alerts, through the same webhook, when the gateway LXC is stopped, when either container is missing or unhealthy, or when the gateway's tailnet DNS stops answering. It alerts after two consecutive failures and again on recovery:

```sh
install -m 755 deploy/proxmox/tepr-watchdog.sh /usr/local/sbin/tepr-watchdog
install -m 644 deploy/proxmox/tepr-watchdog.{service,timer} /etc/systemd/system/
printf 'CTID=103\nGATEWAY_DNS=<gateway tailnet IP>\nALERT_WEBHOOK_URL=<url>\n' > /etc/default/tepr-watchdog
systemctl daemon-reload && systemctl enable --now tepr-watchdog.timer
```

## Availability and recovery

The gateway is a single point of failure for every device routed through it, and for tailnet DNS when the tailnet nameserver points at it.

- **Gateway down, exit devices:** devices using the gateway as their exit node lose Internet access until it returns or they switch exit node. This is the intended fail-closed behaviour.
- **Gateway down, other devices:** with the gateway listed first and a public resolver (for example `9.9.9.9`) second, Tailscale's resolver races the configured nameservers, so devices not using the exit keep resolving through the second one. MagicDNS names keep working because 100.100.100.100 answers them locally.
- **Restarts:** the LXC starts on boot (`onboot=1`) and both containers use `restart: unless-stopped`. Routing and DNS are fail-closed until the first reconcile after start, which retries every 2 s while Tailscale comes up.

What to back up:

| Data | Where | Covered by |
| --- | --- | --- |
| Tailscale node identity | `tailscale-state` Docker volume, on the LXC root disk | the LXC backup (vzdump) |
| Loaded images | Docker, on the LXC root disk | the LXC backup; they can also be rebuilt from git |
| Desired state, catalog, Proton session and profiles, UI secrets, TLS | the app directory (`.env`, `state/`, `config/`, `proton-broker-state/`, `proton-configs/`, `ui-auth/`, `tls/`) | snapshots of the dataset holding it; bind mounts are not in vzdump |

To recover, restore the LXC backup and the app directory, then run `docker compose up -d --no-build`. If only the app directory survives, run the same command on a fresh LXC. It registers a new Tailscale node, which must be approved as an exit node again; after that, re-point the tailnet DNS nameserver at the new node's address.

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