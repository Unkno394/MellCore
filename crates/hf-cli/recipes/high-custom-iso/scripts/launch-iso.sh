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
high_virt_type=${HF_HIGH_VIRT_TYPE:-kvm}
case "$high_virt_type" in kvm|qemu) ;; *) echo "invalid High libvirt domain type: $high_virt_type" >&2; exit 1 ;; esac
libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}
getent passwd "$libvirt_user" >/dev/null || { echo "libvirt QEMU user does not exist: $libvirt_user" >&2; exit 1; }
setfacl -m "u:$libvirt_user:--x" "$(dirname "$root_dir")" "$root_dir"
base_parent=$(dirname "$base_iso")
while [ "$base_parent" != / ]; do
  setfacl -m "u:$libvirt_user:--x" "$base_parent"
  base_parent=$(dirname "$base_parent")
done
setfacl -m "u:$libvirt_user:r--" "$base_iso"
setfacl -m "u:$libvirt_user:rwx" "$instance_dir"
install_iso=$base_iso
installer=${HF_HIGH_ISO_INSTALLER:-interactive}
install_boot=cdrom,hd
arch_install_method=
arch_repo_iso=
case ${HF_HIGH_ISO_INSTALLER:-interactive}:$(test -e "$instance_dir/installed-disk-verified" && echo installed || echo pending) in
  ubuntu:pending|debian:pending|arch:pending)
    sh "$script_dir/prepare-unattended-iso.sh" "$base_iso" "$instance_id" "$HF_HIGH_ISO_INSTALLER"
    install_iso="$instance_dir/unattended.iso"
    setfacl -m "u:$libvirt_user:r--" "$install_iso"
    ;;
esac
[ "$installer" != arch ] || install_boot=cdrom,hd,menu=off,useserial=on
if [ "$installer" = arch ] && [ ! -e "$instance_dir/installed-disk-verified" ]; then
  method_file="$instance_dir/arch-install-method"
  if [ -r "$method_file" ]; then
    arch_install_method=$(cat "$method_file")
  elif virsh dominfo "$vm_name" >/dev/null 2>&1 || [ -e "$instance_dir/disk.qcow2" ]; then
    # Pre-existing deployments were created before the repository CD-ROM existed.
    # Keep their proven rootfs-copy path unless an operator starts a fresh trap.
    arch_install_method=legacy
    umask 077; printf '%s\n' "$arch_install_method" > "$method_file"
  else
    arch_install_method=${HF_HIGH_ARCH_INSTALL_METHOD:-archinstall}
    umask 077; printf '%s\n' "$arch_install_method" > "$method_file"
  fi
  case "$arch_install_method" in
    archinstall)
      arch_repo_cache=${HF_HIGH_ARCH_REPO_CACHE:-$(dirname "$root_dir")/images/arch-repo}
      arch_repo_iso=$(python3 "$script_dir/prepare-arch-repository.py" "$arch_repo_cache")
      [ -f "$arch_repo_iso" ] || { echo 'HF_HIGH_ERROR code=ARCH_REPO_CACHE_INVALID stage=arch-repository: repository builder returned no ISO' >&2; exit 1; }
      repo_parent=$(dirname "$arch_repo_iso")
      setfacl -m "u:$libvirt_user:--x" "$(dirname "$repo_parent")" "$repo_parent"
      setfacl -m "u:$libvirt_user:r--" "$arch_repo_iso"
      ;;
    legacy) : ;;
    *) echo 'HF_HIGH_ERROR code=ARCH_INSTALL_METHOD_INVALID stage=configuration: expected archinstall or legacy' >&2; exit 1 ;;
  esac
fi
if ! virsh dominfo "$vm_name" >/dev/null 2>&1; then
  [ -f "$instance_dir/disk.qcow2" ] || qemu-img create -f qcow2 "$instance_dir/disk.qcow2" 40G
  setfacl -m "u:$libvirt_user:rw-" "$instance_dir/disk.qcow2"
  if [ -e "$instance_dir/installed-disk-verified" ]; then
    virt-install --virt-type "$high_virt_type" --name "$vm_name" --memory 2048 --vcpus 2 --os-variant generic --import \
      --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" --boot hd \
      --network "network=$HF_HIGH_NETWORK_NAME,model=virtio" \
      --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
      --graphics spice,listen=127.0.0.1 --serial pty --console pty,target.type=serial --noautoconsole
  else
    if [ "$arch_install_method" = archinstall ]; then
      virt-install --virt-type "$high_virt_type" --name "$vm_name" --memory 2048 --vcpus 2 --os-variant generic \
        --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
        --cdrom "$install_iso" --disk "path=$arch_repo_iso,device=cdrom,readonly=on" --boot "$install_boot" \
        --network "network=$HF_HIGH_NETWORK_NAME,model=virtio" \
        --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
        --graphics spice,listen=127.0.0.1 --serial pty --console pty,target.type=serial --noautoconsole
    else
      virt-install --virt-type "$high_virt_type" --name "$vm_name" --memory 2048 --vcpus 2 --os-variant generic \
        --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
        --cdrom "$install_iso" --boot "$install_boot" \
        --network "network=$HF_HIGH_NETWORK_NAME,model=virtio" \
        --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
        --graphics spice,listen=127.0.0.1 --serial pty --console pty,target.type=serial --noautoconsole
    fi
  fi
  lifecycle_log=${HF_HIGH_LIFECYCLE_LOG:-$instance_dir/lifecycle-events.jsonl}
  printf '{"event_id":"%s","state":"VM_CREATED","occurred_at_unix_ms":%s,"detail":null}\n' \
    "$(cat /proc/sys/kernel/random/uuid)" "$(date +%s%3N)" >> "$lifecycle_log"
  chmod 0600 "$lifecycle_log"
fi
if [ "$arch_install_method" = archinstall ]; then
  virsh domblklist "$vm_name" --details | grep -F "$arch_repo_iso" >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_REPO_MEDIA_DEVICE_MISSING stage=installation: domain does not contain the repository CD-ROM' >&2
    exit 1
  }
fi
case ${HF_HIGH_ISO_INSTALLER:-interactive} in
  arch) sh "$script_dir/install-arch.sh" "$instance_id" ;;
  ubuntu|debian) sh "$script_dir/finalize-linux-install.sh" "$instance_id" "$HF_HIGH_ISO_INSTALLER" ;;
  interactive) : ;;
  *) echo "unsupported ISO installer adapter: $HF_HIGH_ISO_INSTALLER" >&2; exit 1 ;;
esac
