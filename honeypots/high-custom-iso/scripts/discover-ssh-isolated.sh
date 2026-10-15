#!/bin/sh
set -eu
instance_id=${1:?instance UUID}; _external_port=${2:-0}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"; vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
sh "$script_dir/create-network.sh"
attempt=1; attempts=${HF_HIGH_DHCP_ATTEMPTS:-120}; guest_ip=
case "$attempts" in ''|*[!0-9]*) echo 'DHCP attempt limit must be numeric' >&2; exit 1 ;; esac
[ "$attempts" -ge 1 ] && [ "$attempts" -le 180 ] || { echo 'DHCP attempt limit is outside 1..180' >&2; exit 1; }
while [ "$attempt" -le "$attempts" ]; do
  guest_ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
  [ -n "$guest_ip" ] && break
  sleep 5
  attempt=$((attempt + 1))
done
[ -n "$guest_ip" ] || { echo 'custom installer did not obtain an isolated DHCP lease' >&2; exit 1; }
python3 - "$guest_ip" "$HF_HIGH_DHCP_START" "$HF_HIGH_DHCP_END" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or not ipaddress.ip_address(sys.argv[2]) <= address <= ipaddress.ip_address(sys.argv[3]):
    raise SystemExit("guest address is outside the High DHCP range")
PY
tmp=$(mktemp "$instance_dir/.guest-ip.XXXXXX")
trap 'rm -f "$tmp"' EXIT INT TERM
printf '%s\n' "$guest_ip" > "$tmp"; chmod 0600 "$tmp"; mv "$tmp" "$instance_dir/guest-ip"
printf '%s\n' 22 > "$instance_dir/guest-service-port"
rm -f "$instance_dir/external-ssh-port" "$instance_dir/publish-interface"
trap - EXIT INT TERM
