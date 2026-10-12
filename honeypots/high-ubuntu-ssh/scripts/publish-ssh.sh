#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
external_port=${2:?external TCP port}
vm_name="hf-high-$instance_id"
bridge=virbr-hfhigh
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}

case "$external_port" in
  ''|*[!0-9]*) echo "external SSH port must be numeric" >&2; exit 1 ;;
esac
[ "$external_port" -ge 1 ] && [ "$external_port" -le 65535 ] || {
  echo "external SSH port is outside 1..65535" >&2
  exit 1
}
# Re-assert the isolated network and guest-to-host firewall policy after host/agent restarts.
sh "$(dirname "$0")/create-network.sh"
# A host listener means this port is already occupied by SSH, the agent, or another service.
# Do not steal it with a NAT rule.
if ss -H -ltn "( sport = :$external_port )" 2>/dev/null | grep -q .; then
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

sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C PREROUTING -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22" 2>/dev/null ||
  iptables -t nat -A PREROUTING -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
iptables -C FORWARD -p tcp -d "$guest_ip" --dport 22 -j ACCEPT 2>/dev/null ||
  iptables -A FORWARD -p tcp -d "$guest_ip" --dport 22 -j ACCEPT
iptables -C FORWARD -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
  iptables -A FORWARD -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
printf '%s\n' "$guest_ip" > "$root_dir/$instance_id/guest-ip"
