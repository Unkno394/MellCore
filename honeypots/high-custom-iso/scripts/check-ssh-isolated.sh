#!/bin/sh
set -eu
instance_id=${1:?instance UUID}; root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
[ -r "$instance_dir/guest-ip" ]; guest_ip=$(cat "$instance_dir/guest-ip")
if iptables-save -t nat 2>/dev/null | grep -F -- "--to-destination $guest_ip:22" >/dev/null; then echo 'custom guest SSH has unexpected DNAT publication' >&2; exit 1; fi
if iptables-save -t filter 2>/dev/null | grep -F -- "-d $guest_ip/32" | grep -F -- '--dport 22' >/dev/null; then echo 'custom guest SSH has unexpected forwarding exception' >&2; exit 1; fi
[ ! -e "$instance_dir/external-ssh-port" ]; [ ! -e "$instance_dir/publish-interface" ]
ipt -C INPUT -i "$HF_HIGH_BRIDGE" -j "$HF_HIGH_INPUT_CHAIN"
ipt -C "$HF_HIGH_INPUT_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -C "$HF_HIGH_INPUT_CHAIN" -j DROP
ipt -C FORWARD -i "$HF_HIGH_BRIDGE" -j "$HF_HIGH_FORWARD_CHAIN"
ipt -C FORWARD -o "$HF_HIGH_BRIDGE" -j "$HF_HIGH_FORWARD_CHAIN"
ipt -C "$HF_HIGH_FORWARD_CHAIN" -j DROP
