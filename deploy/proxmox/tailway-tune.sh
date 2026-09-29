#!/usr/bin/env bash
# Network tuning for the gateway on a Proxmox host, run by tailway-tune.timer.
# Turns on UDP GRO forwarding (Tailscale's recommended offload for exit nodes)
# along the gateway's path: the host uplink, the LXC's host-side interfaces,
# and the interfaces inside the LXC. Interfaces recreated by a restart lose the
# setting, so the timer reapplies it; the agent sets its own interface itself.
# Socket buffer defaults are set once, in /etc/sysctl.d (see docs/guide.md).
set -uo pipefail

CONFIG=${TAILWAY_WATCHDOG_CONFIG:-/etc/default/tailway-watchdog}
# shellcheck source=/dev/null
[[ -r $CONFIG ]] && . "$CONFIG"
CTID=${CTID:-103}

enable() { # interface [nsenter arguments...]
    local interface=$1
    shift
    "$@" ethtool -k "$interface" 2>/dev/null | grep -q '^rx-udp-gro-forwarding: on' && return 0
    if "$@" ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null; then
        logger -t tailway-tune "UDP GRO forwarding enabled on $interface${1:+ (LXC $CTID)}"
    fi
}

# The host's uplink bridge, its physical ports, and the LXC's own interfaces.
bridge=$(ip -o route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
if [[ -n $bridge ]]; then
    enable "$bridge"
    for port in /sys/class/net/"$bridge"/brif/*; do
        port=$(basename "$port")
        [[ -e /sys/class/net/$port/device ]] && enable "$port"
    done
fi
for path in /sys/class/net/{veth,fwbr,fwpr,fwln}"$CTID"[ip]*; do
    [[ -e $path ]] && enable "$(basename "$path")"
done

# Inside the LXC: its uplink and Docker's bridges and veths.
pid=$(lxc-info -n "$CTID" -p -H 2>/dev/null) || exit 0
[[ -n $pid ]] || exit 0
for interface in $(nsenter -t "$pid" -n ip -o link show | awk -F': ' '{sub(/@.*/, "", $2); print $2}'); do
    [[ $interface == lo ]] || enable "$interface" nsenter -t "$pid" -n
done
