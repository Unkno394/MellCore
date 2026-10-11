#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
vm_name="hf-high-$instance_id"
instance_dir="$root_dir/$instance_id"

# Remove only the exact rules written by publish-ssh.sh.  The instance directory is
# still present at this point, so an interrupted deployment is also cleaned up.
if [ -r "$instance_dir/guest-ip" ] && [ -r "$instance_dir/external-ssh-port" ]; then
  guest_ip=$(cat "$instance_dir/guest-ip")
  external_port=$(cat "$instance_dir/external-ssh-port")
  iptables -t nat -D PREROUTING -p tcp --dport "$external_port" -j DNAT --to-destination "$guest_ip:22" 2>/dev/null || true
  iptables -D FORWARD -p tcp -d "$guest_ip" --dport 22 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -p tcp -s "$guest_ip" --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
fi

virsh destroy "$vm_name" 2>/dev/null || true
virsh undefine "$vm_name" --nvram 2>/dev/null || true
rm -rf "$instance_dir"
