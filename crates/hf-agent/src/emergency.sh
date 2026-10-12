#!/bin/sh
# Managed by HoneyForge
set -eu
umask 077

incident=${1:?incident marker required}
[ -f "$incident" ] || exit 1
[ "$(stat -c %u "$incident")" = 0 ] || exit 1
[ "$(stat -c %a "$incident")" = 600 ] || exit 1
trap_id=$(sed -n '1p' "$incident")
response_armed=$(sed -n '3p' "$incident")
printf '%s\n' "$trap_id" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 1
[ "$response_armed" = 'armed=1' ] || exit 1

logger -t honeyforge-emergency "confirmed escape from trap $trap_id; isolating host"
project="/var/lib/honeyforge/traps/$trap_id/compose.yaml"
if [ -f "$project" ]; then
    compact_id=$(printf '%s' "$trap_id" | tr -d '-')
    timeout 10 docker compose --project-name "hf-$compact_id" --file "$project" stop \
        || logger -t honeyforge-emergency "could not stop trap $trap_id before host shutdown"
fi

# Isolate host traffic after the agent has persisted the incident and given the
# Center a short opportunity to ACK it. Failure to install this firewall must
# not prevent the final shutdown step.
if command -v nft >/dev/null 2>&1; then
    nft add table inet honeyforge_emergency 2>/dev/null || true
    nft 'add chain inet honeyforge_emergency output { type filter hook output priority -100; policy drop; }' 2>/dev/null || true
    nft 'add chain inet honeyforge_emergency input { type filter hook input priority -100; policy drop; }' 2>/dev/null || true
    nft 'add chain inet honeyforge_emergency forward { type filter hook forward priority -100; policy drop; }' 2>/dev/null || true
else
    logger -t honeyforge-emergency 'nft is unavailable; powering off without a firewall rule'
fi
sync
systemctl poweroff
