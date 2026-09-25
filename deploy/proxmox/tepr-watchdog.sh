#!/usr/bin/env bash
# Watchdog for the gateway, run on the Proxmox host by tepr-watchdog.timer.
# The agent alerts on its own problems; this covers the agent being unable to:
# the LXC stopped, a container unhealthy or gone, or tailnet DNS not answering.
# A check alerts after FAILURES_BEFORE_ALERT consecutive failures and again when
# it recovers. State lives in /run, so nothing is written to the boot disk.
set -uo pipefail

CONFIG=${TEPR_WATCHDOG_CONFIG:-/etc/default/tepr-watchdog}
# shellcheck source=/dev/null
[[ -r $CONFIG ]] && . "$CONFIG"

CTID=${CTID:-103}
CONTAINERS=${CONTAINERS:-"tailscale-exit-policy-router-agent tailscale-exit-policy-router-broker"}
GATEWAY_DNS=${GATEWAY_DNS:-}
DNS_PROBE_NAME=${DNS_PROBE_NAME:-example.com}
FAILURES_BEFORE_ALERT=${FAILURES_BEFORE_ALERT:-2}
ALERT_WEBHOOK_URL=${ALERT_WEBHOOK_URL:-}
ALERT_WEBHOOK_FORMAT=${ALERT_WEBHOOK_FORMAT:-ntfy}
ALERT_SOURCE=${ALERT_SOURCE:-$(hostname)-watchdog}
STATE_DIR=${STATE_DIR:-/run/tepr-watchdog}

mkdir -p "$STATE_DIR"

notify() { # kind title message
    local kind=$1 title=$2 message=$3
    logger -t tepr-watchdog "$kind: $title: $message"
    [[ -n $ALERT_WEBHOOK_URL ]] || return 0
    if [[ $ALERT_WEBHOOK_FORMAT == json ]]; then
        python3 -c 'import json,sys; print(json.dumps(dict(zip(["source","kind","title","message"], sys.argv[1:]))))' \
            "$ALERT_SOURCE" "$kind" "$title" "$message" |
            curl -fsS -m 10 --retry 3 -H 'Content-Type: application/json' --data-binary @- "$ALERT_WEBHOOK_URL" >/dev/null
    else
        local priority=default tags=white_check_mark
        [[ $kind == problem ]] && priority=high tags=warning
        printf '%s' "$message" |
            curl -fsS -m 10 --retry 3 -H "Title: $ALERT_SOURCE: $title" -H "Priority: $priority" \
                -H "Tags: $tags" --data-binary @- "$ALERT_WEBHOOK_URL" >/dev/null
    fi || logger -t tepr-watchdog "alert delivery failed"
}

record() { # check-name problem-message-or-empty
    local name=$1 problem=$2 file="$STATE_DIR/$1"
    local count=0
    [[ -r $file ]] && count=$(head -n1 "$file")
    if [[ -z $problem ]]; then
        if ((count >= FAILURES_BEFORE_ALERT)); then
            notify resolved "Resolved: $name" "The $name check passes again."
        fi
        rm -f "$file"
        return
    fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$file"
    if ((count == FAILURES_BEFORE_ALERT)); then
        notify problem "Problem: $name" "$problem"
    fi
}

status=$(pct status "$CTID" 2>&1)
if [[ $status != "status: running" ]]; then
    record lxc "Gateway LXC $CTID is not running ($status); tailnet exit routing and DNS are down."
    # The other checks cannot pass and would only repeat this alert.
    exit 0
fi
record lxc ""

problems=()
for container in $CONTAINERS; do
    health=$(pct exec "$CTID" -- docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null) ||
        health="missing"
    [[ $health == running/healthy ]] || problems+=("$container is $health")
done
record containers "$(IFS=';'; echo "${problems[*]}")"

if [[ -n $GATEWAY_DNS ]]; then
    if answer=$(dig +short +time=3 +tries=2 "@$GATEWAY_DNS" "$DNS_PROBE_NAME" A 2>&1) && [[ -n $answer ]]; then
        record dns ""
    else
        record dns "The gateway DNS server $GATEWAY_DNS did not resolve $DNS_PROBE_NAME: ${answer:-no answer}"
    fi
fi
