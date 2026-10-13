#!/bin/sh
set -eu

instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
vm_name="hf-high-$instance_id"
instance_dir="$root_dir/$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
validate_instance_id "$instance_id"

sh "$script_dir/unpublish-ssh.sh" "$instance_id"

virsh destroy "$vm_name" 2>/dev/null || true
virsh undefine "$vm_name" --nvram 2>/dev/null || true
rm -rf "$instance_dir"
