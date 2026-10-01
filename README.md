# Tailway

Tailway turns one machine on your [Tailscale](https://tailscale.com) network into an exit node that sends each device's Internet traffic where you choose: through a VPN, straight out, or nowhere.

- **A route per device.** Send each device through a VPN location, directly to the Internet, or keep it on the local network. New devices are blocked until you choose.
- **Any WireGuard VPN.** Import a configuration from Mullvad, IVPN, AirVPN, your own server, or any other WireGuard provider. Proton VPN also works with account sign-in and server browsing (unofficial).
- **Fails closed.** When a tunnel stops passing traffic, its devices are blocked instead of falling back to your normal connection. DNS follows the same route, with a kill switch.
- **A web console** with a dashboard, per-device settings, health checks, alerts (Telegram or webhook), and password recovery by email.

> [!WARNING]
> **Tailway is alpha software** (version `0.1.0-alpha.1`). It works, but it has had little testing outside its first installation. Expect bugs, and expect settings, stored data, and behaviour to change between releases without an upgrade path. Read the [changelog](CHANGELOG.md) before upgrading, and don't rely on it yet where a routing mistake would be costly. It routes IPv4 only and runs on Linux with Docker.

## Requirements

- A Linux host with Docker Compose and WireGuard support in the kernel (Linux 5.6 or later).
- A Tailscale account where you can approve exit nodes and change DNS settings.

## Quick start

```sh
git clone https://github.com/envin3/tailway.git && cd tailway
cp .env.example .env    # set HOST_BIND_IP to this host's LAN address

mkdir -p config proton-configs proton-broker-state state tls ui-auth
echo '{"schemaVersion":1,"servers":[]}' > config/catalog.json
sudo chgrp -R 1000 config proton-configs proton-broker-state state tls ui-auth   # 1000 = CONTROL_GID
chmod 770 proton-broker-state state
chmod 2770 config proton-configs ui-auth
chmod 750 tls

# A self-signed certificate for the console (or bring your own as tls/tls.crt and tls/tls.key)
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=tailway" \
  -keyout tls/tls.key -out tls/tls.crt
sudo chgrp 1000 tls/tls.* && chmod 640 tls/tls.*

docker compose up -d --build
docker compose exec gateway-agent tailscale up --hostname=tailway \
  --advertise-exit-node --accept-dns=false --netfilter-mode=off
```

## First-time setup

1. Open the link printed by `tailscale up` to add the gateway to your tailnet. Then, in the Tailscale admin console, approve **tailway** as an exit node.
2. Still in the admin console, under **DNS**, add the gateway's tailnet IP address as a nameserver, with a public resolver such as `9.9.9.9` second, and turn on **Override DNS servers**. This lets each device's DNS follow its route.
3. Open `https://<HOST_BIND_IP>:8443` and create the console account. Do this right away: until an account exists, anyone who can reach the page can create it.
4. Add a location: **Locations → Import WireGuard**, or sign in to Proton under **Settings**.
5. On **Devices**, choose a route for each device. Then, on each device, select **tailway** as the exit node in Tailscale. The **Exit node** column shows which devices have.

For a trusted certificate on your tailnet instead of the self-signed one:

```sh
docker compose exec gateway-agent tailscale serve --bg https+insecure://localhost:8443
```

The console is then at `https://tailway.<your-tailnet>.ts.net`.

## Configuration

Most settings live in the console. `.env` holds the few that apply at startup:

| Setting | Default | Purpose |
| --- | --- | --- |
| `HOST_BIND_IP` | (required) | Host address the console listens on |
| `HOST_TAILSCALE_UDP_PORT` | `41641` | Tailscale's UDP port; change it if the host already runs Tailscale |
| `CONTROL_GID` | `1000` | Group that owns the data directories |
| `UNASSIGNED_POLICY` | `block` | What devices without a route get: `block`, `local`, or `direct` |
| `DNS_DEFAULT_SERVER` | `9.9.9.9` | DNS server for devices not routed through a VPN |
| `DNS_KILL_SWITCH_DEFAULT` | `true` | Block DNS while a device's VPN is down |
| `LOG_FORMAT` | `text` | `json` for one JSON object per line, for log collectors |
| `LOG_LEVEL` | `info` | Log detail: `debug`, `info`, `warn`, or a filter such as `tailway=debug` |
| `TAILSCALE_LOG` | `warnings` | `verbose` to include all of Tailscale's own messages |
| `METRICS` | `true` | Prometheus metrics at `http://<gateway tailnet IP>:METRICS_PORT/metrics`, on the tailnet only |
| `METRICS_PORT` | `9091` | Port for Prometheus metrics |

## Proton VPN support

Proton support is unofficial. Tailway uses Proton's open-source Linux client library to sign in, list servers, and issue a WireGuard certificate for each location. It is not endorsed by Proton and may stop working when Proton changes that library. Use it with your own account, at your own risk. Two-factor codes are supported; security keys are not.

Importing Proton's downloadable WireGuard configurations, like any other provider's, works without signing in.

## Security

- The console is HTTPS only. Keep port 8443 on a trusted network or your tailnet; never forward it from the Internet.
- The routing container gets network administration rights inside its own network namespace only. It has no host network, Docker socket, or privileged mode.
- WireGuard private keys, the Proton session, and the console account stay on the host, in `state/`, `proton-configs/`, `proton-broker-state/`, and `ui-auth/`. Back them up and protect them like passwords.

## Documentation

[docs/guide.md](docs/guide.md) explains routing, DNS, health checks, alerts, account recovery, backups, and troubleshooting.

## Versions

Tailway follows [Semantic Versioning](https://semver.org); alpha releases are `0.x.y-alpha.N`. [CHANGELOG.md](CHANGELOG.md) lists what each release changes, and [docs/releasing.md](docs/releasing.md) how releases are made. The running version is shown in the console's sidebar and in `GET /v1/status`, or run `docker compose exec gateway-agent gateway-agent --version`.

## Development

```sh
cargo test
cargo build --bins
```

Rust 1.85 or later. `DRY_RUN=true` makes the agent write its rules without applying them.

## License

Tailway is free software under the [GNU General Public License v3.0 or later](LICENSE).

Tailway is an independent project. It is not affiliated with or endorsed by Tailscale Inc. or Proton AG.
