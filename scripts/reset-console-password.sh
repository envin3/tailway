#!/bin/sh
# Resets the console password from the server, for when it is lost and email
# recovery is not set up. Every console session ends; recovery settings stay.
#
#   scripts/reset-console-password.sh [username]
#
# Run it where the gateway runs: on its Docker host, or on a Proxmox host whose
# LXC runs it (found through pct; set GATEWAY_CTID if it is not 103).
set -eu

container=${AGENT_CONTAINER:-tailscale-exit-policy-router-agent}
control_gid=${CONTROL_GID:-1000}
ctid=${GATEWAY_CTID:-103}

# How to run a command next to the gateway's containers.
if command -v docker >/dev/null 2>&1 && docker inspect "$container" >/dev/null 2>&1; then
    run() { docker "$@"; }
    where="this host"
elif command -v pct >/dev/null 2>&1 && pct exec "$ctid" -- docker inspect "$container" >/dev/null 2>&1; then
    run() { pct exec "$ctid" -- docker "$@"; }
    where="LXC $ctid"
else
    echo "The gateway container ($container) is not running here." >&2
    echo "Run this script where the gateway runs: on the Proxmox host (it reaches LXC $ctid" >&2
    echo "through pct; set GATEWAY_CTID for another LXC), or inside that LXC." >&2
    exit 1
fi

read_secret() {
    printf "%s" "$1" >&2
    stty -echo
    trap 'stty echo' EXIT INT TERM
    IFS= read -r value
    stty echo
    trap - EXIT INT TERM
    printf "\n" >&2
    printf "%s" "$value"
}

echo "Resetting the console password of the gateway in $where." >&2
password=$(read_secret "New console password (at least 12 characters): ")
confirmation=$(read_secret "Repeat it: ")
[ "$password" = "$confirmation" ] || { echo "The passwords do not match." >&2; exit 1; }

if [ $# -gt 0 ]; then
    printf '%s\n' "$password" | run exec -i -u "65532:$control_gid" "$container" gateway-ui reset-password --username "$1"
else
    printf '%s\n' "$password" | run exec -i -u "65532:$control_gid" "$container" gateway-ui reset-password
fi
unset password confirmation
