#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
instance_dir="$root_dir/$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
bridge=$HF_HIGH_BRIDGE
validate_instance_id "$instance_id"
[ -r "$instance_dir/guest-ip" ]
[ -r "$instance_dir/external-ssh-port" ]
[ -r "$instance_dir/publish-interface" ]
guest_ip=$(cat "$instance_dir/guest-ip")
external_port=$(cat "$instance_dir/external-ssh-port")
publish_interface=$(cat "$instance_dir/publish-interface")
validate_publish_interface_name "$publish_interface"
guest_port=22
[ -r "$instance_dir/guest-service-port" ] && guest_port=$(cat "$instance_dir/guest-service-port")
ipt -t nat -C PREROUTING -j "$HF_HIGH_DNAT_CHAIN"
ipt -C INPUT -i "$bridge" -j "$HF_HIGH_INPUT_CHAIN"
ipt -C "$HF_HIGH_INPUT_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -C "$HF_HIGH_INPUT_CHAIN" -j DROP
ipt -C FORWARD -i "$bridge" -j "$HF_HIGH_FORWARD_CHAIN"
ipt -C FORWARD -o "$bridge" -j "$HF_HIGH_FORWARD_CHAIN"
ipt -t nat -C "$HF_HIGH_DNAT_CHAIN" -i "$publish_interface" -m addrtype --dst-type LOCAL -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:$guest_port"
nat_port_has_only_expected_claim "$external_port" "$HF_HIGH_DNAT_CHAIN" "$publish_interface" "$guest_ip:$guest_port"
ipt -C "$HF_HIGH_FORWARD_CHAIN" -i "$publish_interface" -o "$bridge" -p tcp -d "$guest_ip" --dport "$guest_port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
ipt -C "$HF_HIGH_FORWARD_CHAIN" -i "$bridge" -o "$publish_interface" -p tcp -s "$guest_ip" --sport "$guest_port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -C "$HF_HIGH_FORWARD_CHAIN" -j DROP
if command -v ip6tables >/dev/null 2>&1; then
  ip6t -C INPUT -i "$bridge" -j "$HF_HIGH_INPUT6_CHAIN"
  ip6t -C "$HF_HIGH_INPUT6_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6t -C FORWARD -i "$bridge" -j "$HF_HIGH_FORWARD6_CHAIN"
  ip6t -C FORWARD -o "$bridge" -j "$HF_HIGH_FORWARD6_CHAIN"
  ip6t -C "$HF_HIGH_INPUT6_CHAIN" -j DROP
  ip6t -C "$HF_HIGH_FORWARD6_CHAIN" -j DROP
fi
