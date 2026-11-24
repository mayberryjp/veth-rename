#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -f -- "$tmp"/firewall-drops.log* "$tmp/config" "$tmp/state"; rmdir -- "$tmp"' EXIT
log="$tmp/firewall-drops.log"
sed -e "s|/var/log/veth-manager/firewall-drops.log|$log|" \
    -e '/^[[:space:]]*su root root$/d' deploy/veth-manager.logrotate > "$tmp/config"
chmod 0600 "$tmp/config"

# Missing and empty logs must not create archives.
logrotate --state "$tmp/state" "$tmp/config"
touch "$log"
logrotate --force --state "$tmp/state" "$tmp/config"
[[ ! -e "$log.1.gz" ]]

# Keep the writer open to verify that copytruncate preserves its destination.
exec 3>>"$log"
printf 'first record\n' >&3
logrotate --state "$tmp/state" "$tmp/config"
[[ ! -e "$log.1.gz" ]]
truncate -s 10485761 "$log"
logrotate --state "$tmp/state" "$tmp/config"
[[ ! -s "$log" && -f "$log.1.gz" ]]
gzip -t "$log.1.gz"
printf 'after rotation\n' >&3
[[ "$(cat "$log")" == 'after rotation' ]]

# A small log rotates once a day even when below the size threshold.
sed -i -E 's/[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}-[0-9:]+/2000-1-1-0:0:0/' "$tmp/state"
logrotate --state "$tmp/state" "$tmp/config"
[[ ! -s "$log" && "$(gzip -cd "$log.1.gz")" == 'after rotation' ]]

for i in {1..8}; do
    printf 'record %s\n' "$i" >&3
    logrotate --force --state "$tmp/state" "$tmp/config"
done
exec 3>&-
[[ "$(gzip -cd "$log.1.gz")" == 'record 8' ]]
[[ "$(gzip -cd "$log.7.gz")" == 'record 2' ]]
[[ ! -e "$log.8.gz" ]]
printf 'Validated firewall log rotation and retention\n'
