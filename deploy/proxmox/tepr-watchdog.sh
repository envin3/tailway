#!/usr/bin/env bash
# Watchdog for the gateway, run on the Proxmox host by tepr-watchdog.timer.
# The agent alerts on its own problems; this covers the agent being unable to:
# the LXC stopped, a container unhealthy or gone, or tailnet DNS not answering.
# A check alerts after FAILURES_BEFORE_ALERT consecutive failures and again when
# it recovers, through the channels set on the console's Alerts page. State
# lives in /run, so nothing is written to the boot disk.
set -uo pipefail

CONFIG=${TEPR_WATCHDOG_CONFIG:-/etc/default/tepr-watchdog}
# shellcheck source=/dev/null
[[ -r $CONFIG ]] && . "$CONFIG"

CTID=${CTID:-103}
CONTAINERS=${CONTAINERS:-"tailscale-exit-policy-router-agent tailscale-exit-policy-router-broker"}
GATEWAY_DNS=${GATEWAY_DNS:-}
DNS_PROBE_NAME=${DNS_PROBE_NAME:-example.com}
FAILURES_BEFORE_ALERT=${FAILURES_BEFORE_ALERT:-2}
# The alert channels configured on the console's Alerts page.
ALERT_SETTINGS=${ALERT_SETTINGS:-/mnt/main/appdata/tailscale-exit-policy-router/state/alerts.json}
ALERT_SOURCE=${ALERT_SOURCE:-$(hostname)-watchdog}
STATE_DIR=${STATE_DIR:-/run/tepr-watchdog}

mkdir -p "$STATE_DIR"

notify() { # kind title message
    local kind=$1 title=$2 message=$3
    logger -t tepr-watchdog "$kind: $title: $message"
    [[ -r $ALERT_SETTINGS ]] || return 0
    python3 - "$ALERT_SETTINGS" "$ALERT_SOURCE" "$kind" "$title" "$message" <<'PY' || logger -t tepr-watchdog "alert delivery failed"
import json
import sys
import urllib.request

path, source, kind, title, message = sys.argv[1:]
with open(path, encoding="utf-8") as file:
    settings = json.load(file)
failed = False


def post(url, body, headers):
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


telegram = settings.get("telegram")
if telegram:
    icon = {"problem": "\u26a0\ufe0f", "resolved": "\u2705"}.get(kind, "\u2139\ufe0f")
    text = f"{icon} {title}\n{message}\n\n{source}"
    try:
        post(
            f"https://api.telegram.org/bot{telegram['botToken']}/sendMessage",
            json.dumps({"chat_id": telegram["chatId"], "text": text}).encode(),
            {"Content-Type": "application/json"},
        )
    except Exception as error:  # the URL holds the bot token: report the type only
        print(f"telegram: {type(error).__name__}", file=sys.stderr)
        failed = True

webhook = settings.get("webhook")
if webhook:
    try:
        if webhook.get("format") == "json":
            body = {"source": source, "key": title, "kind": kind, "title": title, "message": message}
            post(webhook["url"], json.dumps(body).encode(), {"Content-Type": "application/json"})
        else:
            post(webhook["url"], message.encode(), {
                "Title": f"{source}: {title}",
                "Priority": "high" if kind == "problem" else "default",
                "Tags": "warning" if kind == "problem" else "white_check_mark",
            })
    except Exception as error:
        print(f"webhook: {type(error).__name__}", file=sys.stderr)
        failed = True

sys.exit(1 if failed else 0)
PY
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
