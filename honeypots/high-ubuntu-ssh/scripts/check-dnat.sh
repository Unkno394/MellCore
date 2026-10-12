#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
instance_dir="$root_dir/$instance_id"
[ -r "$instance_dir/guest-ip" ]
[ -r "$instance_dir/external-ssh-port" ]
guest_ip=$(cat "$instance_dir/guest-ip")
external_port=$(cat "$instance_dir/external-ssh-port")
iptables -t nat -C PREROUTING -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22"
iptables -C FORWARD -p tcp -d "$guest_ip" --dport 22 -j ACCEPT
iptables -C FORWARD -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
