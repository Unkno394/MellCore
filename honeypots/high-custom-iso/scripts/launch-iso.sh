#!/bin/sh
set -eu
base_iso=${1:?verified custom ISO}; instance_id=${2:?instance UUID}; _external_port=${3:-0}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"; vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
command -v virsh >/dev/null; command -v virt-install >/dev/null; command -v qemu-img >/dev/null; command -v setfacl >/dev/null
sh "$script_dir/create-network.sh"
mkdir -p "$instance_dir"
libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}
getent passwd "$libvirt_user" >/dev/null || { echo "libvirt QEMU user does not exist: $libvirt_user" >&2; exit 1; }
setfacl -m "u:$libvirt_user:--x" "$(dirname "$root_dir")" "$root_dir" "$(dirname "$(dirname "$base_iso")")" "$(dirname "$base_iso")"
setfacl -m "u:$libvirt_user:r--" "$base_iso"
setfacl -m "u:$libvirt_user:rwx" "$instance_dir"
install_iso=$base_iso
case ${HF_HIGH_ISO_INSTALLER:-interactive}:$(test -e "$instance_dir/installed-disk-verified" && echo installed || echo pending) in
  ubuntu:pending|debian:pending|arch:pending)
    sh "$script_dir/prepare-unattended-iso.sh" "$base_iso" "$instance_id" "$HF_HIGH_ISO_INSTALLER"
    install_iso="$instance_dir/unattended.iso"
    setfacl -m "u:$libvirt_user:r--" "$install_iso"
    ;;
esac
if ! virsh dominfo "$vm_name" >/dev/null 2>&1; then
  [ -f "$instance_dir/disk.qcow2" ] || qemu-img create -f qcow2 "$instance_dir/disk.qcow2" 40G
  setfacl -m "u:$libvirt_user:rw-" "$instance_dir/disk.qcow2"
  if [ -e "$instance_dir/installed-disk-verified" ]; then
    virt-install --name "$vm_name" --memory 2048 --vcpus 2 --os-variant generic --import \
      --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" --boot hd \
      --network "network=$HF_HIGH_NETWORK_NAME,model=virtio" \
      --channel "unix,path=$instance_dir/telemetry.sock,mode=bind,target.type=virtio,target.name=org.honeyforge.telemetry.0" \
      --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
      --graphics spice,listen=127.0.0.1 --serial pty --console pty,target.type=serial --noautoconsole
  else
    virt-install --name "$vm_name" --memory 2048 --vcpus 2 --os-variant generic \
      --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
      --cdrom "$install_iso" --boot cdrom,hd \
      --network "network=$HF_HIGH_NETWORK_NAME,model=virtio" \
      --channel "unix,path=$instance_dir/telemetry.sock,mode=bind,target.type=virtio,target.name=org.honeyforge.telemetry.0" \
      --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
      --graphics spice,listen=127.0.0.1 --serial pty --console pty,target.type=serial --noautoconsole
  fi
  lifecycle_log=${HF_HIGH_LIFECYCLE_LOG:-$instance_dir/lifecycle-events.jsonl}
  printf '{"event_id":"%s","state":"VM_CREATED","occurred_at_unix_ms":%s,"detail":null}\n' \
    "$(cat /proc/sys/kernel/random/uuid)" "$(date +%s%3N)" >> "$lifecycle_log"
  chmod 0600 "$lifecycle_log"
fi
case ${HF_HIGH_ISO_INSTALLER:-interactive} in
  arch) sh "$script_dir/install-arch.sh" "$instance_id" ;;
  ubuntu|debian) sh "$script_dir/finalize-linux-install.sh" "$instance_id" "$HF_HIGH_ISO_INSTALLER" ;;
  interactive) : ;;
  *) echo "unsupported ISO installer adapter: $HF_HIGH_ISO_INSTALLER" >&2; exit 1 ;;
esac
