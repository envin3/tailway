#!/bin/sh
set -eu

root_directory=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
auth_directory="$root_directory/ui-auth"
control_gid=${CONTROL_GID:-1000}

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

mkdir -p "$auth_directory"
printf "Console password: " >&2
stty -echo
IFS= read -r password
stty echo
printf "\n" >&2

printf '%s' "$password" \
  | docker run --rm -i httpd:2.4-alpine htpasswd -niBC 12 admin \
  | sed 's/^admin://' \
  > "$auth_directory/password.bcrypt"
unset password
chgrp "$control_gid" "$auth_directory" "$auth_directory/password.bcrypt"
# The console writes its account here when the password is changed.
chmod 2770 "$auth_directory"
chmod 640 "$auth_directory/password.bcrypt"
echo "Created UI authentication secrets in $auth_directory"