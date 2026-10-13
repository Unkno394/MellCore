#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
instance_dir="$root_dir/$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
bridge=$HF_HIGH_BRIDGE
validate_instance_id "$instance_id"

if [ ! -r "$instance_dir/guest-ip" ] || [ ! -r "$instance_dir/external-ssh-port" ]; then
  exit 0
fi
guest_ip=$(cat "$instance_dir/guest-ip")
external_port=$(cat "$instance_dir/external-ssh-port")
delete_all nat "$HF_HIGH_DNAT_CHAIN" ! -i "$bridge" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
delete_all filter "$HF_HIGH_FORWARD_CHAIN" ! -i "$bridge" -o "$bridge" -p tcp -d "$guest_ip" --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" ! -o "$bridge" -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Also clean exact rules written by older recipe versions.
delete_all nat PREROUTING -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
delete_all filter FORWARD -p tcp -d "$guest_ip" --dport 22 -j ACCEPT
delete_all filter FORWARD -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
