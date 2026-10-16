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
guest_port=22
[ -r "$instance_dir/guest-service-port" ] && guest_port=$(cat "$instance_dir/guest-service-port")
if [ -r "$instance_dir/publish-interface" ]; then
  publish_interface=$(cat "$instance_dir/publish-interface")
  validate_publish_interface_name "$publish_interface"
  delete_all nat "$HF_HIGH_DNAT_CHAIN" -i "$publish_interface" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
  delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$publish_interface" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" -o "$publish_interface" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
fi

# Clean wildcard-interface rules written by older recipe versions.
delete_all nat "$HF_HIGH_DNAT_CHAIN" ! -i "$bridge" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
delete_all filter "$HF_HIGH_FORWARD_CHAIN" ! -i "$bridge" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
delete_all filter "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" ! -o "$bridge" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

