# Tailway guide

How Tailway works and how to run it. For installation, see the [README](../README.md).

## How it works

Tailway runs as two containers:

- **`gateway-agent`** runs Tailscale as an exit node, one WireGuard tunnel per VPN location in use, the firewall and routing rules, the DNS forwarder, and the web console. The console runs as a separate unprivileged process inside the same container.
- **`proton-broker`** holds the Proton session, if you use Proton. It has no network privileges and never returns session or key material through its API.

Every device on the tailnet is identified by its stable Tailscale node ID. Traffic a device sends through the gateway is marked by its route and steered into that route's tunnel through its own routing table. The forwarding policy drops anything not explicitly allowed. Each tunnel's routing table ends in an `unreachable` route, so if a tunnel disappears, its traffic, and the gateway's own DNS queries for it, fail instead of leaving through the host's connection.

## Routes

Each device gets one of these routes on the **Devices** page:

- **A VPN location**: through that location's tunnel. One tunnel is shared by every device using the same location. It starts when the first device picks the location and stops when the last one leaves.
- **Direct Internet**: through the host's own connection, without a VPN. If the host itself runs a VPN, direct traffic follows it.
- **Local network only**: tailnet and private addresses only; no Internet.
- **Default**: follows `UNASSIGNED_POLICY`. The default, `block`, means a new or forgotten device never reaches the Internet through the gateway by accident.

When a device's route changes, its open connections are reset, so existing flows don't keep using the old route.

A route applies only once the device has selected the gateway as its exit node in Tailscale. Tailscale does not tell an exit node who selected it, so Tailway works it out from traffic. A device that sent Internet-bound traffic through the gateway in the last 15 minutes shows **Selected** in the **Exit node** column, including traffic that was then blocked. A device that has the exit node selected but sends nothing for 15 minutes shows **Not selected** until it does.

## Health checks

Every tunnel is checked on each reconcile (every 30 seconds) in two ways.

**Handshakes.** A tunnel is *healthy* when its last WireGuard handshake is under 180 seconds old and *degraded* up to 300 seconds; traffic stays in the tunnel either way. It is *failed* beyond that, or when no handshake arrives within 60 seconds of starting. Failed, missing, or downed tunnels are recreated automatically. Every peer gets `PersistentKeepalive = 25` if its configuration lacks one, so idle tunnels keep handshaking.

**Traffic.** A handshake proves only that the server answers. A provider can complete handshakes for a key it no longer forwards traffic for; Proton does once a certificate expires. So each tunnel with a good handshake also sends real packets:

- a public-address lookup (OpenDNS, falling back to Cloudflare). A successful one shows the location's **public IP** in the console;
- a query to the tunnel's own DNS resolver, when its configuration names one.

One failed lookup marks the location *degraded*. Two in a row mark it *failed*: its devices are blocked, and the tunnel is recreated then and every ten failures after that. Two unanswered resolver queries in a row mark it *degraded*.

**Why.** Each location's status comes with a reason code (`statusReason` in `GET /v1/exits`):

| Code | Meaning |
| --- | --- |
| `handshake.waiting` | Just created; waiting for the first handshake |
| `handshake.no_reply` | Nothing at all has come back from the server since the tunnel was created. The server may be unreachable, or not accepting this key (a revoked key or certificate, or an account connection limit) |
| `handshake.never` | The server replies, but no handshake has completed |
| `handshake.stale`, `handshake.lost` | Handshakes stopped: degraded, then failed |
| `probe.egress` | Handshakes work but traffic doesn't pass |
| `probe.resolver` | The tunnel's DNS resolver doesn't answer |
| `tunnel.setup`, `tunnel.unreadable` | The tunnel could not be created or inspected; the message says why |

### The health registry

Besides the locations, the gateway checks itself on every reconcile: its routing rules, Tailscale, its connection to Tailscale's coordination server, its Tailscale key's expiry, the DNS forwarder, each VPN-routed device's use of the exit node, the Proton session and certificate, and the host's free disk space (for `state/`), clock synchronisation, and connection-tracking table. The dashboard's **Health checks** card shows them all. `GET /v1/health` returns each check's status (`ok`, `unknown`, `warning`, `failed`), reason code, message, when the status last changed, and when the check was last OK.

The gateway's own checks record every change in the activity history, even a short one that never becomes an alert. In particular, **Tailscale connection** turns to a warning when the coordination server doesn't see the gateway as online, or Tailscale reports a problem. Devices, Apple ones especially, can then show the exit node as unavailable even though tunnels keep working.

Alerts come from these checks: a failed location at once, failed routing after 90 seconds, Tailscale down after 3 minutes, the gateway's connection to Tailscale lost for 5 minutes, its Tailscale key within 14 days of expiring, a signed-out Proton session after 10 minutes, low disk space (under 200 MB) after 10 minutes, and a connection table over 80% full after 5 minutes. An unsynchronised clock shows on the dashboard without an alert.

For the container runtime and monitors, the control socket also answers:

- `GET /healthz`: 200 while the reconcile loop keeps completing passes (whatever their result). The container's healthcheck uses it, so only a stuck agent is restarted.
- `GET /readyz`: 200 when Tailscale runs, the routing rules are applied, and the DNS forwarder answers; otherwise 503 with the reasons.

## DNS

By default, Tailscale answers an exit-node client's DNS lookups on the exit node itself, over the exit node's normal connection. The lookups of a VPN-routed device would then leak to your Internet provider, and the gateway couldn't tell which device asked.

Tailway therefore includes a per-device DNS forwarder. In the Tailscale admin console, under **DNS**:

1. Add the gateway's tailnet IPv4 address as a nameserver, then a public resolver (or your home router) as a second one, and turn on **Override DNS servers**.
2. Keep **Allow local network access** off on devices that use the exit node.

MagicDNS keeps working: devices answer tailnet names themselves and forward only other names. The forwarder sees which device asked:

| Device | Its DNS |
| --- | --- |
| Routed to a VPN location | The resolver named in the location's configuration (`DNS =`; `10.2.0.1` for Proton), inside that device's tunnel. Without one, the device's DNS server, still inside the tunnel. |
| VPN down, kill switch on (the default) | Nothing resolves (`SERVFAIL`) |
| VPN down, kill switch off | The device's DNS server, over the host's connection |
| Direct, Local only, Default, or not using the exit node | The device's DNS server (default `DNS_DEFAULT_SERVER`, `9.9.9.9`) |

Change a device's kill switch or DNS server in its **DNS** panel on the **Devices** page. `DNS_KILL_SWITCH_DEFAULT` sets the default kill switch; `DNS_FORWARDER=false` turns the forwarder off.

Answers are cached, separately for each route, so an answer fetched through one tunnel is never given to a device on another. A cached answer is kept for its TTL, at most 5 minutes (1 minute for names that don't exist), and a device whose VPN is down with the kill switch on still gets `SERVFAIL`. Queries carrying EDNS options, such as DNS cookies, are always forwarded.

Only tailnet addresses (`100.64.0.0/10`) are answered. Until the gateway's Tailscale is running with the tailnet's device list, every lookup gets `SERVFAIL`, because an unknown device would otherwise be sent to the default server. After a restart this normally lasts a few seconds.

If the gateway is down, devices not using the exit node keep resolving through the second nameserver. Devices using it get no DNS until it returns, because their traffic still goes to the unavailable exit node.

## Any WireGuard VPN

On **Locations**, choose **Import WireGuard**, then pick the `.conf` file or paste it. Give it a name, a provider, and a country; a file named like `mullvad-ch-zrh-wg-001.conf` fills these in. The location then appears in every device's route menu, under its provider.

- **Requirements:** exactly one `[Peer]`, with an `Endpoint` and `AllowedIPs` including `0.0.0.0/0`. Otherwise WireGuard would drop what the gateway sends into the tunnel. IPv6 addresses are ignored.
- **Ignored settings:** `wg-quick`-only settings are dropped and never run: `PostUp` and the other scripts, `Table`, `FwMark`, `MTU`, and `SaveConfig`.
- **DNS:** the `DNS =` line names the tunnel's resolver.
- **Storage:** each configuration is a private file (`0600`) in `state/custom-exits/`, named by a random ID. The API never returns it.
- **Removing:** once no device uses a location, **Remove** deletes it, including its private key.
- **Keys:** key rotation is the provider's business. If a provider revokes or replaces a key, import the new configuration. The health checks mark a tunnel that stops passing traffic as failed, and alert.

## Proton VPN

Proton support is unofficial; see the README. Sign in under **Settings → Proton VPN**. The password and two-factor code go only to Proton, through the broker; they are not stored. The broker keeps a refreshable session in `proton-broker-state/` with owner-only permissions. Protect and back up that directory like a password.

**Add Proton server** on **Locations** browses Proton's servers by country, with load and feature filters. Adding one generates its WireGuard profile in `proton-configs/`. Profiles are never returned to the browser or the routing API.

- **Keys:** each Proton location gets its own WireGuard key, because Proton lets a key be active on only one server at a time. Several tunnels sharing a key keep taking the session from each other, and each drops traffic for seconds at a time.
- **Certificates:** Proton authorises each key with a certificate valid for about a week. With an expired certificate, Proton servers still complete handshakes but forward nothing. The broker renews each certificate when Proton's refresh time passes, and checks every profile against its key at startup and every five minutes, rewriting any that don't match. A new sign-in renews every certificate and keeps the keys.
- **Connection limit:** Proton's connection limit counts Proton tunnels only. At the limit, a new Proton location is refused, but devices can still share or switch existing ones.
- **Library version:** the broker installs exact versions of Proton's `proton-vpn-api-core` (`PROTON_CORE_VERSION`) and `proton-core` (`PROTON_PYTHON_CORE_VERSION`), the ones it was tested with. Proton's package repository keeps older releases, so builds stay reproducible when Proton publishes new ones. To try a newer release, raise both and test signing in, server browsing, and certificate renewal.

## Console account

The console account is created on the first visit. Sign-up closes as soon as it exists. To set the password in advance instead, so sign-up never appears, run `scripts/create-ui-secrets.sh` before starting. Change the username and password on **Settings → Account & security**. Changing the password signs out every other session.

**Sessions** use an `HttpOnly`, `Secure`, `SameSite=Strict` cookie, plus a per-session CSRF token for every change. A session ends when the browser closes, after 30 minutes idle, or after 12 hours. With **Keep me signed in on this device** ticked at sign-in, it lasts until the browser goes 30 days without visiting, and at most 180 days, and it survives restarts and upgrades. Only a hash of each remembered session is stored, in `ui-auth/sessions.json`. **Settings → Account & security → Sign out other browsers** ends every session but your own, and so does changing or resetting the password. Sign-in must come from the console's own origin. Ten failed attempts from one address within five minutes block that address for the rest of the window. Existing sessions keep working. Behind `tailscale serve`, all clients share one address for this limit.

**A forgotten password** can be reset two ways:

- **By email.** Set up **Password recovery by email** on **Settings → Account & security**: a recovery address, and an SMTP server to send from. For Gmail or iCloud, use an app password. Changing these settings needs the current password, because whoever controls them can reset it. **Forgot password?** on the sign-in page then emails an 8-digit code that works once, for 10 minutes, with five attempts.
- **On the server**, while the stack runs: `scripts/reset-console-password.sh [username]`. It also works on a Proxmox host whose LXC runs the gateway; set `GATEWAY_CTID` to that LXC's ID.

## Alerts

Set up notifications on **Settings → Notifications**, through Telegram, a webhook, or both:

- **Telegram:** create a bot with @BotFather, paste its token, message the bot, then use **Find chat**.
- **Webhook:** an [ntfy](https://ntfy.sh) topic URL, or any endpoint that accepts JSON (`{source, key, kind, title, message}`).

Settings are stored in `state/alerts.json` (`0600`). The bot token is never shown again. You are notified when a problem outlasts its grace period, and again when it clears:

| Problem | Grace |
| --- | --- |
| A location is failed (its devices are blocked) | None |
| Applying routing keeps failing | 90 seconds |
| Tailscale on the gateway is not running | 3 minutes |
| The Proton session is signed out, or the broker is unreachable | 10 minutes |
| Proton certificate renewal is not running, or a certificate expires within 24 hours | None |
| A device routed through a VPN stops using the gateway as its exit node: it did before, is online, and has sent no Internet traffic through the gateway for 15 minutes | 10 minutes |

The gateway also sends a message whenever it starts. Current problems appear on the dashboard and under `alerts` in `GET /v1/status`.

The gateway cannot report its own absence. On Proxmox, `deploy/proxmox/` has a watchdog for the host that runs every two minutes. It alerts, through the same channels, when the gateway's LXC is stopped, a container is unhealthy, or the gateway's DNS stops answering:

```sh
install -m 755 deploy/proxmox/tailway-watchdog.sh /usr/local/sbin/tailway-watchdog
install -m 644 deploy/proxmox/tailway-watchdog.{service,timer} /etc/systemd/system/
printf 'CTID=<gateway LXC ID>\nGATEWAY_DNS=<gateway tailnet IP>\nALERT_SETTINGS=<app directory>/state/alerts.json\n' > /etc/default/tailway-watchdog
systemctl daemon-reload && systemctl enable --now tailway-watchdog.timer
```

## Availability and backups

The gateway is a single point of failure for every device that uses it as exit node. If it goes down, those devices lose Internet access until it returns or they pick another exit node. That is the intended fail-closed behaviour. Both containers restart automatically. Routing and DNS stay closed until the first successful reconcile after a start, which retries every two seconds while Tailscale comes up.

Back up:

| Data | Where |
| --- | --- |
| The gateway's Tailscale identity | The `tailscale-state` Docker volume |
| Routes, locations, alerts, console account, TLS, Proton session and profiles | The app directory: `.env`, `state/`, `config/`, `proton-configs/`, `proton-broker-state/`, `ui-auth/`, `tls/` |

To restore, put both back and run `docker compose up -d`. Without the `tailscale-state` volume, the gateway joins the tailnet as a new device. Approve it as an exit node again and point the tailnet's DNS setting at its new address.

## Performance

The gateway routes IPv4 only. It refuses IPv6 from devices immediately (a TCP reset, or ICMP for other protocols), so apps fall back to IPv4 without waiting. For this, `compose.yaml` turns on IPv6 forwarding in the agent's container; nothing is forwarded.

At startup the agent turns on UDP GRO forwarding on its own network interface. Tailscale recommends this for exit nodes because it cuts the CPU cost per packet. For the full benefit, turn it on along the rest of the path too, and let Tailscale use large UDP socket buffers:

- **Any Linux host:** `ethtool -K <uplink> rx-udp-gro-forwarding on rx-gro-list off`, for example from a `post-up` line of the interface.
- **Proxmox, gateway in an LXC:** `deploy/proxmox/tailway-tune.sh` sets it on the host's uplink and on the LXC's interfaces, and a timer reapplies it after the container restarts. It reads `CTID` from `/etc/default/tailway-watchdog`:

  ```sh
  install -m 755 deploy/proxmox/tailway-tune.sh /usr/local/sbin/tailway-tune
  install -m 644 deploy/proxmox/tailway-tune.{service,timer} /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now tailway-tune.timer
  ```

- **Socket buffers:** in an unprivileged container, Tailscale cannot raise its buffers itself and logs `failed to force-set UDP read buffer size`. It then uses the kernel's defaults, which only the host can change. Buffers are allocated only while data is queued.

  ```sh
  printf 'net.core.rmem_max = 7340032\nnet.core.wmem_max = 7340032\nnet.core.rmem_default = 7340032\nnet.core.wmem_default = 7340032\n' > /etc/sysctl.d/90-tailway.conf
  sysctl --system
  ```

  The warning remains in the log after the change; it's harmless.

A single device's speed is normally limited by its VPN location, not the gateway. On a 4-core Intel N150, the Tailscale leg alone carried about 1.4 Gbit/s using about one core.

## Running on another host

To run images built elsewhere, copy `compose.yaml` and `.env`, load the images with `docker load`, set `IMAGE_TAG` in `.env`, and start with `docker compose up -d --no-build`.

## Metrics

The dashboard shows the last 24 hours of each location under its name: its state in 15-minute steps (green healthy, amber degraded, red down) and a line of download throughput, with the peak rate and the latest probe round trip. The history is kept in `state/metrics.json`, saved hourly and when the agent stops; `GET /v1/metrics/history` returns it, one point per minute.

For Prometheus, Grafana, or similar, the agent serves the current values at `http://<gateway tailnet IP>:9091/metrics`. It listens on the tailnet address only, so any device on your tailnet can read it and nothing else can. It includes each location's state, handshake age, bytes sent and received, and probe round trip; reconcile passes, failures and duration; DNS queries, cache hits and failures; every health check's status; and the number of active alerts. `METRICS=false` turns it off, and `METRICS_PORT` changes the port. Location and check names appear as labels, so anyone who can reach it sees them.

## Activity

The **Activity** page, and **Recent activity** on the dashboard, show what happened on the gateway:

- **Locations and routes:** a location connecting, degrading, going down or recovering, its public IP changing, and each device whose route changed, with the reason, e.g. `envin-desktop: ES#146 → blocked while ES#146 is down`.
- **Changes:** every settings change made in the console or the API, with the console user and their address, e.g. `Set the route of envin-desktop to NL#227`. Rejected requests are recorded too.
- **Sign-ins:** successful and failed sign-ins with the client address, blocked addresses, password changes, and password resets by email or on the server. Failed sign-ins don't record the username that was tried.
- **Alerts** raised and resolved, and the gateway starting and stopping.

Behind `tailscale serve`, the client address is the device's tailnet address, taken from the header Tailscale adds.

The history is stored as JSON lines in `state/events/`, in five files of up to 1 MB each (many months of normal activity). The oldest file is dropped when the newest fills. Unlike the container logs, it survives restarts and upgrades. `GET /v1/events` returns it, newest first, with optional `category` (`health`, `change`, `access`, `system`), `severity` (minimum: `info`, `warning`, `error`), `search`, `before` (Unix time, for paging), and `limit` (up to 500).

## Logs

`docker compose logs gateway-agent` shows the agent, the console, and Tailscale. Of Tailscale's own messages, its warnings and errors always show, and so do its connection-state messages: the coordination server, relays, which path each device uses, network changes, and its health reports. These explain why a device lost the exit node. Its other routine messages are hidden unless `TAILSCALE_LOG=verbose`. `LOG_LEVEL=debug` adds detail, and `LOG_FORMAT=json` writes one JSON object per line for collectors such as Loki or journald. Logs rotate at 10 MB, five files per container, and are lost when a container is replaced.

Passwords, tokens, private keys, and password hashes are never written to the log: the types that hold them print `<redacted>`, and a test fails if one stops doing so.

## Troubleshooting

**Diagnose a location.** On **Locations**, **Diagnose** tests a running location now:

1. It checks the tunnel interface and the last handshake.
2. It sends real traffic through the tunnel, comparing the bytes sent and received.
3. It asks the tunnel's DNS resolver.
4. It tries the server's address on TCP 443 outside the tunnel, to see whether the host is up.

It then says what the result most likely means. For example, "the server's host is up, but nothing comes back through WireGuard" points to the provider not accepting the key, not to your gateway. `POST /v1/exits/{id}/diagnose` returns the same.

**Report a bug.** **Activity → Download support bundle** (or `GET /v1/support-bundle`) saves a JSON summary: version, settings, locations, health checks, alerts, and recent activity. Device names are replaced with `device-1`, `device-2`, …, tailnet addresses are hidden, and it contains no keys, tokens, passwords, or console user names. Read it before you share it.

Common problems:


- **Direct connections fail, and traffic goes through Tailscale relays.** The gateway's Tailscale listens on `HOST_TAILSCALE_UDP_PORT`. It must be a free UDP port on the host, and published unchanged.
- **The agent cannot write its runtime files.** Keep the `runtime` volume in `compose.yaml` as a tmpfs. The agent deliberately lacks the capabilities to override file ownership, so leftover files from a bind mount block it.
- **The broker fails with `PermissionError`.** Its code is copied into the image with the broker's user and `CONTROL_GID`. Keep `CONTROL_GID` in `.env` matching the build.
- **A location handshakes but passes no traffic.** For Proton, check the certificate and session on **Settings → Proton VPN**. For other providers, the key may have been revoked; import a new configuration.

## Security model

The agent runs as root only inside its own network namespace, with `NET_ADMIN`, `SETUID`, and `SETGID` plus `/dev/net/tun`. It deliberately lacks `DAC_OVERRIDE` and `FOWNER`, so host file permissions still apply to it. `SETUID` and `SETGID` are used only to start the console as UID 65532 with `CONTROL_GID`. The console keeps neither, and `no-new-privileges` prevents getting them back. There is no Docker socket, host network, `SYS_ADMIN`, `SYS_MODULE`, or privileged mode. If the console exits unexpectedly, the container stops and Compose restarts it.

The API accepts only logical node, location, and route IDs. System commands are run with explicit argument lists, never through a shell. State is written to `0600` temporary files, synced, and renamed into place, with revision checks against concurrent changes.
