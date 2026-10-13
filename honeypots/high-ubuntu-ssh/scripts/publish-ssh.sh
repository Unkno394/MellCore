#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
external_port=${2:?external TCP port}
vm_name="hf-high-$instance_id"
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
bridge=$HF_HIGH_BRIDGE
validate_instance_id "$instance_id"

case "$external_port" in
  ''|*[!0-9]*) echo "external SSH port must be numeric" >&2; exit 1 ;;
esac
[ "$external_port" -ge 1 ] && [ "$external_port" -le 65535 ] || {
  echo "external SSH port is outside 1..65535" >&2
  exit 1
}
if is_protected_tcp_port "$external_port"; then
  sh "$script_dir/unpublish-ssh.sh" "$instance_id"
  echo "external SSH port is reserved for host management: $external_port" >&2
  exit 1
fi
# Re-assert the isolated network and guest-to-host firewall policy after host/agent restarts.
sh "$script_dir/create-network.sh"
# A host listener means this port is already occupied by SSH, the agent, or another service.
# Do not steal it with a NAT rule.
if ss -H -ltn "( sport = :$external_port )" 2>/dev/null | grep -q .; then
  sh "$script_dir/unpublish-ssh.sh" "$instance_id"
  echo "external SSH port is already in use on the VPS: $external_port" >&2
  exit 1
fi

guest_ip=
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  guest_ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
  [ -n "$guest_ip" ] && break
  sleep 5
done
[ -n "$guest_ip" ] || { echo "VM did not obtain an isolated DHCP lease" >&2; exit 1; }
python3 - "$guest_ip" <<'PY'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
first = ipaddress.ip_address("192.168.250.100")
last = ipaddress.ip_address("192.168.250.200")
if address.version != 4 or not first <= address <= last:
    raise SystemExit("libvirt returned an address outside the High DHCP range")
PY

if [ -r "$root_dir/$instance_id/guest-ip" ]; then
  previous_guest_ip=$(cat "$root_dir/$instance_id/guest-ip")
  if [ "$previous_guest_ip" != "$guest_ip" ]; then
    sh "$script_dir/unpublish-ssh.sh" "$instance_id"
  fi
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Migrate the exact legacy rules before checking whether Docker/UFW/libvirt owns this port.
delete_all nat PREROUTING -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
delete_all filter FORWARD -p tcp -d "$guest_ip" --dport 22 -j ACCEPT
delete_all filter FORWARD -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
delete_all nat "$HF_HIGH_DNAT_CHAIN" ! -i "$bridge" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
delete_all filter "$HF_HIGH_FORWARD_CHAIN" ! -i "$bridge" -o "$bridge" -p tcp -d "$guest_ip" --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" ! -o "$bridge" -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
if nat_port_is_claimed_elsewhere "$external_port"; then
  echo "external SSH port already has a host NAT/redirect rule: $external_port" >&2
  exit 1
fi

ipt -t nat -I "$HF_HIGH_DNAT_CHAIN" 1 ! -i "$bridge" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
ipt -I "$HF_HIGH_FORWARD_CHAIN" 1 ! -i "$bridge" -o "$bridge" -p tcp -d "$guest_ip" --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
ipt -I "$HF_HIGH_FORWARD_CHAIN" 1 -i "$bridge" ! -o "$bridge" -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
printf '%s\n' "$guest_ip" > "$root_dir/$instance_id/guest-ip"
