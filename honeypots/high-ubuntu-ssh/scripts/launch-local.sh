#!/bin/sh
set -eu

base_image=${1:?path to a bootable QCOW2 image is required}
instance_id=${2:?instance UUID is required}
external_port=${3:?external SSH port is required}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/local/high}
instance_dir="$root_dir/$instance_id"
vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/firewall-common.sh"
validate_instance_id "$instance_id"
case "$external_port" in
  ''|*[!0-9]*) echo "external SSH port must be numeric" >&2; exit 1 ;;
esac
[ "$external_port" -ge 1 ] && [ "$external_port" -le 65535 ] || {
  echo "external SSH port is outside 1..65535" >&2
  exit 1
}

for tool in qemu-img virsh virt-install setfacl sha256sum python3 getent; do
  command -v "$tool" >/dev/null || { echo "required High runtime command is missing: $tool" >&2; exit 1; }
done
[ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] || {
  echo "High traps require accessible /dev/kvm" >&2
  exit 1
}
[ -f "$base_image" ] && [ -r "$base_image" ] || {
  echo "High image is not a readable regular file: $base_image" >&2
  exit 1
}
base_image=$(realpath -- "$base_image")
qemu-img info --output=json "$base_image" | python3 -c '
import json, sys
image = json.load(sys.stdin)
if image.get("format") != "qcow2":
    raise SystemExit("High image must use QCOW2 format")
if not isinstance(image.get("virtual-size"), int) or image["virtual-size"] <= 0:
    raise SystemExit("High image has no valid virtual size")
'

sh "$script_dir/create-network.sh"
virsh dominfo "$vm_name" >/dev/null 2>&1 && {
  echo "refusing to adopt existing libvirt domain $vm_name" >&2
  exit 1
}
mkdir -p "$instance_dir"
chmod 0700 "$instance_dir"
printf '%s\n' "$external_port" > "$instance_dir/external-ssh-port"
cleanup_needed=1
cleanup_failed_launch() {
  status=$?
  if [ "$cleanup_needed" -eq 1 ]; then
    virsh destroy "$vm_name" >/dev/null 2>&1 || true
    virsh undefine "$vm_name" --nvram >/dev/null 2>&1 || true
    sh "$script_dir/unpublish-ssh.sh" "$instance_id" >/dev/null 2>&1 || true
    rm -rf -- "$instance_dir"
  fi
  trap - EXIT INT TERM
  exit "$status"
}
trap cleanup_failed_launch EXIT INT TERM

qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$instance_dir/disk.qcow2"
mac_suffix=$(printf '%s' "$instance_id" | sha256sum | cut -c1-8 | sed 's/../&:/g; s/:$//')
guest_mac="52:54:$mac_suffix"
printf '%s\n' "$guest_mac" > "$instance_dir/mac-address"

libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}
getent passwd "$libvirt_user" >/dev/null || {
  echo "libvirt QEMU user does not exist: $libvirt_user" >&2
  exit 1
}
setfacl -m "u:$libvirt_user:--x" \
  "$(dirname "$root_dir")" "$(dirname "$(dirname "$root_dir")")" "$root_dir" \
  "$(dirname "$(dirname "$base_image")")" "$(dirname "$base_image")"
setfacl -m "u:$libvirt_user:r--" "$base_image"
setfacl -m "u:$libvirt_user:rw-" "$instance_dir/disk.qcow2"
setfacl -m "u:$libvirt_user:rwx" "$instance_dir"

virt-install \
  --connect qemu:///system \
  --virt-type kvm \
  --name "$vm_name" \
  --memory 2048 \
  --vcpus 2 \
  --import \
  --os-variant generic \
  --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
  --network "network=$HF_HIGH_NETWORK_NAME,model=virtio,mac=$guest_mac" \
  --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
  --graphics none \
  --noautoconsole

cleanup_needed=0
trap - EXIT INT TERM
