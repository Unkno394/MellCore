#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
external_port=${2:?external TCP port}
guest_port=${3:-22}
vm_name="hf-high-$instance_id"
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
bridge=$HF_HIGH_BRIDGE
validate_instance_id "$instance_id"
dhcp_diagnostic=${HF_HIGH_DIAGNOSE_DHCP:-0}
case "$dhcp_diagnostic" in 0|1) ;; *) echo "invalid DHCP diagnostic mode" >&2; exit 1 ;; esac
dhcp_failure_marker="$root_dir/$instance_id/dhcp-timeout"
[ "$dhcp_diagnostic" -eq 0 ] || rm -f "$dhcp_failure_marker"

case "$external_port" in
  ''|*[!0-9]*) echo "external SSH port must be numeric" >&2; exit 1 ;;
esac
[ "$guest_port" -ge 1 ] 2>/dev/null && [ "$guest_port" -le 65535 ] || {
  echo "guest service port is outside 1..65535" >&2
  exit 1
}
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
publish_interface=$(resolve_high_publish_interface)
# A host listener means this port is already occupied by SSH, the agent, or another service.
# Do not steal it with a NAT rule.
if ss -H -ltn "( sport = :$external_port )" 2>/dev/null | grep -q .; then
  sh "$script_dir/unpublish-ssh.sh" "$instance_id"
  echo "external SSH port is already in use on the VPS: $external_port" >&2
  exit 1
fi

guest_ip=
dhcp_attempts=${HF_HIGH_DHCP_ATTEMPTS:-12}
case "$dhcp_attempts" in
  ''|*[!0-9]*) echo "DHCP attempt limit must be numeric" >&2; exit 1 ;;
esac
[ "$dhcp_attempts" -ge 1 ] && [ "$dhcp_attempts" -le 180 ] || {
  echo "DHCP attempt limit is outside 1..180" >&2
  exit 1
}
attempt=1
while [ "$attempt" -le "$dhcp_attempts" ]; do
  guest_ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
  [ -n "$guest_ip" ] && break
  sleep 5
  attempt=$((attempt + 1))
done
if [ -z "$guest_ip" ]; then
  if [ "$dhcp_diagnostic" -eq 1 ]; then
    umask 077
    : > "$dhcp_failure_marker"
  fi
  echo "VM did not obtain an isolated DHCP lease" >&2
  exit 1
fi
[ "$dhcp_diagnostic" -eq 0 ] || rm -f "$dhcp_failure_marker"
python3 - "$guest_ip" "$HF_HIGH_DHCP_START" "$HF_HIGH_DHCP_END" <<'PY'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
first = ipaddress.ip_address(sys.argv[2])
last = ipaddress.ip_address(sys.argv[3])
if address.version != 4 or not first <= address <= last:
    raise SystemExit("libvirt returned an address outside the High DHCP range")
PY

if [ -r "$root_dir/$instance_id/guest-ip" ]; then
  previous_guest_ip=$(cat "$root_dir/$instance_id/guest-ip")
  if [ "$previous_guest_ip" != "$guest_ip" ]; then
    sh "$script_dir/unpublish-ssh.sh" "$instance_id"
  fi
fi
if [ -r "$root_dir/$instance_id/publish-interface" ]; then
  previous_publish_interface=$(cat "$root_dir/$instance_id/publish-interface")
  validate_publish_interface_name "$previous_publish_interface"
  if [ "$previous_publish_interface" != "$publish_interface" ]; then
    sh "$script_dir/unpublish-ssh.sh" "$instance_id"
  fi
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Remove the wildcard-interface rules emitted by older recipe versions before installing the
# interface-scoped policy.
delete_all nat "$HF_HIGH_DNAT_CHAIN" ! -i "$bridge" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
delete_all filter "$HF_HIGH_FORWARD_CHAIN" ! -i "$bridge" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" ! -o "$bridge" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
delete_all nat "$HF_HIGH_DNAT_CHAIN" -i "$publish_interface" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$publish_interface" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" -o "$publish_interface" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
if nat_port_is_claimed_elsewhere "$external_port"; then
  echo "external SSH port already has a host NAT/redirect rule: $external_port" >&2
  exit 1
fi

# Persist enough exact rule data before adding any firewall rules. If a later rule insertion
# fails, the caller's cleanup path can remove the subset that was already installed.
printf '%s\n' "$guest_ip" > "$root_dir/$instance_id/guest-ip"
printf '%s\n' "$guest_port" > "$root_dir/$instance_id/guest-service-port"
printf '%s\n' "$publish_interface" > "$root_dir/$instance_id/publish-interface"

ipt -t nat -I "$HF_HIGH_DNAT_CHAIN" 1 -i "$publish_interface" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
ipt -I "$HF_HIGH_FORWARD_CHAIN" 1 -i "$publish_interface" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
ipt -I "$HF_HIGH_FORWARD_CHAIN" 1 -i "$bridge" -o "$publish_interface" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

nat_port_has_only_expected_claim "$external_port" "$HF_HIGH_DNAT_CHAIN" "$publish_interface" "$guest_ip:$guest_port" || {
  echo "High published port $external_port does not have exactly one expected DNAT rule" >&2
  exit 1
}
ipt -t nat -C "$HF_HIGH_DNAT_CHAIN" -i "$publish_interface" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
ipt -C "$HF_HIGH_FORWARD_CHAIN" -i "$publish_interface" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
ipt -C "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" -o "$publish_interface" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
python3 - "$guest_ip" "$guest_port" <<'PY'
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
last_error = None
for _ in range(5):
    try:
        with socket.create_connection((host, port), timeout=2) as connection:
            connection.settimeout(2)
            banner = connection.recv(128)
        if port == 22 and not (banner.startswith(b"SSH-2.0-") or banner.startswith(b"SSH-1.99-")):
            raise RuntimeError(f"port 22 returned a non-SSH banner: {banner[:64]!r}")
        raise SystemExit(0)
    except (OSError, RuntimeError) as error:
        last_error = error
        time.sleep(1)
raise SystemExit(f"published High service backend did not answer on {host}:{port}: {last_error}")
PY

echo "High published-port NAT and forwarding rules are installed; guest service answered on $guest_ip:$guest_port"
