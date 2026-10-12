#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
vm_name="hf-high-$instance_id"
instance_dir="$root_dir/$instance_id"

sh "$(dirname "$0")/unpublish-ssh.sh" "$instance_id"

virsh destroy "$vm_name" 2>/dev/null || true
virsh undefine "$vm_name" --nvram 2>/dev/null || true
rm -rf "$instance_dir"
