#!/bin/sh
set -eu
base_iso=${1:?verified Windows ISO}; instance_id=${2:?instance UUID}; _external_port=${3:-0}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"; vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
command -v virsh >/dev/null; command -v virt-install >/dev/null
sh "$script_dir/create-network.sh"
sh "$script_dir/verify-windows-media.sh" "$base_iso" "$instance_dir"
if ! virsh dominfo "$vm_name" >/dev/null 2>&1; then
  sh "$script_dir/create-overlay.sh" "$base_iso" "$instance_dir" "$instance_id"
  virt-install --name "$vm_name" --memory 4096 --vcpus 2 --os-variant win2k22 --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=sata" --cdrom "$base_iso" --disk "path=$instance_dir/seed.iso,device=cdrom,readonly=on" --boot cdrom,hd --network "network=$HF_HIGH_NETWORK_NAME,model=e1000e" --channel "unix,path=$instance_dir/telemetry.sock,mode=bind,target.type=virtio,target.name=org.honeyforge.telemetry.0" --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" --graphics spice,listen=127.0.0.1 --noautoconsole
fi
sh "$script_dir/install-windows.sh" "$instance_id"
rm -f "$instance_dir/external-ssh-port" "$instance_dir/publish-interface"
