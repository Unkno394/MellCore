#!/bin/sh
set -eu

base_image=${1:?verified prepared Windows QCOW2}
instance_id=${2:?instance UUID}
_external_port=${3:-0}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
instance_dir="$root_dir/$instance_id"
vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
command -v virsh >/dev/null
command -v virt-install >/dev/null
command -v setfacl >/dev/null
sh "$script_dir/create-network.sh"
virsh dominfo "$vm_name" >/dev/null 2>&1 && { echo "VM already exists: $vm_name" >&2; exit 1; }
trap 'virsh destroy "$vm_name" >/dev/null 2>&1 || true; virsh undefine "$vm_name" --nvram >/dev/null 2>&1 || true; rm -rf "$instance_dir"' EXIT INT TERM
sh "$script_dir/create-prepared-overlay.sh" "$base_image" "$instance_dir" "$instance_id"

libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}
getent passwd "$libvirt_user" >/dev/null || { echo "libvirt QEMU user does not exist: $libvirt_user" >&2; exit 1; }
setfacl -m "u:$libvirt_user:--x" \
  "$(dirname "$root_dir")" "$root_dir" \
  "$(dirname "$(dirname "$base_image")")" "$(dirname "$base_image")"
setfacl -m "u:$libvirt_user:r--" "$base_image" "$instance_dir/config-drive.iso"
setfacl -m "u:$libvirt_user:rw-" "$instance_dir/disk.qcow2"
setfacl -m "u:$libvirt_user:rwx" "$instance_dir"

virt-install --name "$vm_name" --memory 4096 --vcpus 2 --import --os-variant win2k22 \
  --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$instance_dir/config-drive.iso,device=cdrom,readonly=on" \
  --network "network=hf-high-isolated,model=virtio" \
  --channel "unix,path=$instance_dir/telemetry.sock,mode=bind,target.type=virtio,target.name=org.honeyforge.telemetry.0" \
  --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
  --graphics spice,listen=127.0.0.1 --noautoconsole
trap - EXIT INT TERM
