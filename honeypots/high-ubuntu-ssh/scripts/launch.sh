#!/bin/sh
set -eu

base_image=${1:?verified Ubuntu cloud image}
instance_id=${2:?instance UUID}
ssh_port=${3:?external SSH port}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
instance_dir="$root_dir/$instance_id"
vm_name="hf-high-$instance_id"

command -v virsh >/dev/null
command -v virt-install >/dev/null
"$(dirname "$0")/create-network.sh"

if virsh dominfo "$vm_name" >/dev/null 2>&1; then
  echo "VM already exists: $vm_name" >&2
  exit 1
fi
"$(dirname "$0")/create-overlay.sh" "$base_image" "$instance_dir" "$instance_id"

virt-install \
  --name "$vm_name" \
  --memory 2048 \
  --vcpus 2 \
  --import \
  --os-variant ubuntu24.04 \
  --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$instance_dir/seed.iso,device=cdrom,readonly=on" \
  --network "network=hf-high-isolated,model=virtio" \
  --graphics none \
  --noautoconsole

# The host firewall/NAT adapter must publish ssh_port to this VM only after it receives an IP.
# Keeping it outside the guest ensures the guest cannot alter host exposure.
printf '%s\n' "$ssh_port" > "$instance_dir/external-ssh-port"
