#!/bin/sh
# Managed by HoneyForge
set -eu
umask 077
incident=${1:?incident marker required}
[ "$incident" = /var/lib/honeyforge/security/confirmed-escape ] || exit 1
[ ! -L "$incident" ] && [ -f "$incident" ] || exit 1
[ "$(stat -c %u "$incident")" = 0 ] || exit 1
[ "$(stat -c %a "$incident")" = 600 ] || exit 1
trap_id=$(sed -n '1p' "$incident")
printf '%s\n' "$trap_id" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 1
[ "$(sed -n '3p' "$incident")" = 'armed=1' ] || exit 1
log() { logger -t honeyforge-emergency "$*" || true; }
log "confirmed escape from trap $trap_id; isolating host"
compact_id=$(printf '%s' "$trap_id" | tr -d '-')
# Operate only on the named project; never evaluate a possibly modified compose file.
containers=$(timeout 5 docker ps -q --filter "label=com.docker.compose.project=hf-$compact_id") || containers=''
set --
for container in $containers; do
    case "$container" in *[!0-9a-f]*|'') continue ;; esac
    set -- "$@" "$container"
done
if [ "$#" -gt 0 ]; then
    timeout 10 docker stop --time 3 "$@" || log "trap containers did not stop"
fi
# Own table only. Flush/recreate our chains as one nft transaction so a repeated
# service run cannot silently retain an accept rule left from an earlier run.
if command -v nft >/dev/null 2>&1; then
    timeout 5 nft add table inet honeyforge_emergency 2>/dev/null || true
    if ! timeout 5 nft -f - <<'NFT'
delete table inet honeyforge_emergency
add table inet honeyforge_emergency
add chain inet honeyforge_emergency output { type filter hook output priority -100; policy drop; }
add chain inet honeyforge_emergency input { type filter hook input priority -100; policy drop; }
add chain inet honeyforge_emergency forward { type filter hook forward priority -100; policy drop; }
NFT
    then log 'network isolation failed; continuing to poweroff'; fi
else
    log 'nft unavailable; continuing to poweroff'
fi
timeout 5 sync || log 'sync timed out or failed'
if ! timeout 10 systemctl poweroff; then
    log 'poweroff failed; systemd will retry the emergency service'
    exit 1
fi
