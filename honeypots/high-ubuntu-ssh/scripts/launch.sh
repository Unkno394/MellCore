#!/bin/sh
set -eu

base_image=${1:?verified Ubuntu cloud image}
instance_id=${2:?instance UUID}
ssh_port=${3:?external SSH port}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
instance_dir="$root_dir/$instance_id"
vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
validate_instance_id "$instance_id"

command -v virsh >/dev/null
command -v virt-install >/dev/null
sh "$script_dir/create-network.sh"

if virsh dominfo "$vm_name" >/dev/null 2>&1; then
  echo "VM already exists: $vm_name" >&2
  exit 1
fi

cleanup_needed=1
cleanup_failed_launch() {
  status=$?
  if [ "$cleanup_needed" -eq 1 ]; then
    virsh destroy "$vm_name" >/dev/null 2>&1 || true
    virsh undefine "$vm_name" --nvram >/dev/null 2>&1 || true
    rm -rf "$instance_dir"
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup_failed_launch EXIT INT TERM

sh "$script_dir/create-overlay.sh" "$base_image" "$instance_dir" "$instance_id"

# Operator-provided images are cached below the agent state directory with mode 0600. Grant only
# the libvirt worker the traversal/read access needed for this VM; no directory is made public.
if command -v setfacl >/dev/null 2>&1; then
  libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}
  getent passwd "$libvirt_user" >/dev/null || {
    echo "libvirt QEMU user does not exist: $libvirt_user" >&2
    exit 1
  }
  setfacl -m "u:$libvirt_user:--x" \
    "$(dirname "$root_dir")" "$root_dir" \
    "$(dirname "$(dirname "$base_image")")" "$(dirname "$base_image")"
  setfacl -m "u:$libvirt_user:r--" "$base_image" "$instance_dir/seed.iso"
  setfacl -m "u:$libvirt_user:rw-" "$instance_dir/disk.qcow2"
  setfacl -m "u:$libvirt_user:rwx" "$instance_dir"
fi

high_virt_type=${HF_HIGH_VIRT_TYPE:-kvm}
case "$high_virt_type" in
  kvm|qemu) ;;
  *) echo "invalid High libvirt domain type: $high_virt_type" >&2; exit 1 ;;
esac

virt-install \
  --virt-type "$high_virt_type" \
  --name "$vm_name" \
  --memory 2048 \
  --vcpus 2 \
  --import \
  --os-variant ubuntu24.04 \
  --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$instance_dir/seed.iso,device=cdrom,readonly=on" \
  --network "network=hf-high-isolated,model=virtio" \
  --channel "unix,path=$instance_dir/telemetry.sock,mode=bind,target.type=virtio,target.name=org.honeyforge.telemetry.0" \
  --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
  --graphics none \
  --noautoconsole

# The host firewall/NAT adapter must publish ssh_port to this VM only after it receives an IP.
# Keeping it outside the guest ensures the guest cannot alter host exposure.
if [ "$high_virt_type" = kvm ]; then
  printf '%s\n' "$ssh_port" > "$instance_dir/external-ssh-port"
fi
cleanup_needed=0
trap - EXIT INT TERM
