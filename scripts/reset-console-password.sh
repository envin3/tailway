#!/bin/sh
# Resets the console password from the server, for when it is lost and Telegram
# recovery is not set up. Run on the Docker host while the stack is running:
#   scripts/reset-console-password.sh [username]
# Every console session ends.
set -eu

container=${AGENT_CONTAINER:-tailscale-exit-policy-router-agent}
control_gid=${CONTROL_GID:-1000}

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
docker inspect "$container" >/dev/null 2>&1 || { echo "container $container is not running" >&2; exit 1; }

read_secret() {
    printf "%s" "$1" >&2
    stty -echo
    IFS= read -r value
    stty echo
    printf "\n" >&2
    printf "%s" "$value"
}

password=$(read_secret "New console password (at least 12 characters): ")
confirmation=$(read_secret "Repeat it: ")
[ "$password" = "$confirmation" ] || { echo "The passwords do not match." >&2; exit 1; }

if [ $# -gt 0 ]; then
    printf '%s\n' "$password" | docker exec -i -u "65532:$control_gid" "$container" gateway-ui reset-password --username "$1"
else
    printf '%s\n' "$password" | docker exec -i -u "65532:$control_gid" "$container" gateway-ui reset-password
fi
unset password confirmation
