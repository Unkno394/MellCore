#!/bin/sh
set -eu

base_image=${1:?path to a bootable QCOW2 image is required}
instance_id=${2:?instance UUID is required}
external_port=${3:?external SSH port is required}
guest_os=${HF_HIGH_GUEST_OS:-ubuntu}
case "$guest_os" in ubuntu|debian|arch|windows) ;; *) echo "unsupported High OS: $guest_os" >&2; exit 1 ;; esac
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
    cleanup_failed=0
    if domains=$(virsh list --all --name 2>/dev/null); then
      domain_list_ok=1
    else
      echo "launch cleanup cannot inspect libvirt domains; preserving $instance_dir" >&2
      cleanup_failed=1
      domain_list_ok=0
      domains=
    fi
    if [ "$domain_list_ok" -eq 1 ] && printf '%s\n' "$domains" | grep -Fxq "$vm_name"; then
      vm_state=$(virsh domstate "$vm_name" 2>/dev/null || true)
      if [ "$vm_state" != "shut off" ]; then
        virsh destroy "$vm_name" >/dev/null 2>&1 || true
        vm_state=$(virsh domstate "$vm_name" 2>/dev/null || true)
      fi
      if [ "$vm_state" = "shut off" ]; then
        if virsh undefine "$vm_name" --nvram >/dev/null 2>&1; then
          :
        elif virsh undefine "$vm_name" >/dev/null 2>&1; then
          :
        else
          echo "launch cleanup could not undefine $vm_name; preserving $instance_dir" >&2
          cleanup_failed=1
        fi
      else
        echo "launch cleanup could not stop $vm_name (state: ${vm_state:-unknown}); preserving $instance_dir" >&2
        cleanup_failed=1
      fi
    fi
    if ! sh "$script_dir/unpublish-ssh.sh" "$instance_id"; then
      echo "launch cleanup could not remove published SSH rules; preserving $instance_dir" >&2
      cleanup_failed=1
    fi
    if domains=$(virsh list --all --name 2>/dev/null); then
      if printf '%s\n' "$domains" | grep -Fxq "$vm_name"; then
        echo "launch cleanup left libvirt domain $vm_name defined; preserving $instance_dir" >&2
        cleanup_failed=1
      fi
    else
      echo "launch cleanup could not confirm whether $vm_name remains defined; preserving $instance_dir" >&2
      cleanup_failed=1
    fi
    if [ "$cleanup_failed" -eq 0 ]; then
      rm -rf -- "$instance_dir" || {
        echo "launch cleanup could not remove $instance_dir" >&2
        cleanup_failed=1
      }
    fi
    [ "$cleanup_failed" -eq 0 ] || echo "High launch cleanup was incomplete; retry with hf remove after inspecting libvirt and firewall state" >&2
  fi
  trap - EXIT INT TERM
  exit "$status"
}
trap cleanup_failed_launch EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

virtual_size=$(qemu-img info --output=json "$base_image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
if [ "$guest_os" != windows ] && [ "$virtual_size" -lt 21474836480 ]; then
  virtual_size=21474836480
fi
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$instance_dir/disk.qcow2" "$virtual_size"
if [ "$guest_os" != windows ]; then
  command -v virt-customize >/dev/null || { echo 'Linux High images require virt-customize to prepare guest services before boot' >&2; exit 1; }
  if [ "$guest_os" = arch ]; then
    [ -f "$instance_dir/05-honeyforge-high.network" ] || {
      echo 'Arch network configuration is missing' >&2
      exit 1
    }
    if ! LIBGUESTFS_BACKEND=direct virt-customize -a "$instance_dir/disk.qcow2" --no-network \
      --touch /etc/cloud/cloud-init.disabled \
      --mkdir /etc/systemd/network \
      --upload "$instance_dir/05-honeyforge-high.network:/etc/systemd/network/05-honeyforge-high.network" \
      --run-command 'chown root:root /etc/systemd/network/05-honeyforge-high.network && chmod 0644 /etc/systemd/network/05-honeyforge-high.network' \
      --run-command 'test -x /usr/sbin/qemu-ga || test -x /usr/bin/qemu-ga' \
      --run-command 'systemctl --root=/ mask systemd-time-wait-sync.service' \
      --run-command 'systemctl --root=/ enable qemu-guest-agent.service systemd-networkd.service sshd.service'; then
      echo 'could not prepare Arch guest disk; verify qemu-guest-agent is installed and systemd can enable qemu-guest-agent, systemd-networkd and sshd' >&2
      exit 1
    fi
  else
    if ! LIBGUESTFS_BACKEND=direct virt-customize -a "$instance_dir/disk.qcow2" --no-network \
      --run-command 'test -x /usr/sbin/qemu-ga || test -x /usr/bin/qemu-ga' \
      --run-command 'systemctl --root=/ enable qemu-guest-agent.service'; then
      echo "could not prepare $guest_os guest disk; qemu-guest-agent must be installed and its systemd unit must be enableable before VM launch" >&2
      exit 1
    fi
  fi
fi
mac_suffix=$(printf '%s' "$instance_id" | sha256sum | cut -c1-8 | sed 's/../&:/g; s/:$//')
guest_mac="52:54:$mac_suffix"
printf '%s\n' "$guest_mac" > "$instance_dir/mac-address"

libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}
getent passwd "$libvirt_user" >/dev/null || {
  echo "libvirt QEMU user does not exist: $libvirt_user" >&2
  exit 1
}
setfacl -m "u:$libvirt_user:--x" "$(dirname "$root_dir")" "$(dirname "$(dirname "$root_dir")")" "$root_dir"
base_parent=$(dirname "$base_image")
while [ "$base_parent" != / ]; do
  setfacl -m "u:$libvirt_user:--x" "$base_parent"
  base_parent=$(dirname "$base_parent")
done
setfacl -m "u:$libvirt_user:r--" "$base_image"
setfacl -m "u:$libvirt_user:rw-" "$instance_dir/disk.qcow2"
setfacl -m "u:$libvirt_user:rwx" "$instance_dir"
if [ -f "$instance_dir/seed.iso" ]; then
  setfacl -m "u:$libvirt_user:r--" "$instance_dir/seed.iso"
  set -- --disk "path=$instance_dir/seed.iso,device=cdrom,readonly=on"
else
  set --
fi
if [ "$guest_os" = windows ]; then
  vm_memory=4096
  os_variant=win2k22
  graphics='spice,listen=127.0.0.1'
else
  vm_memory=2048
  os_variant=generic
  graphics=none
fi

virt-install \
  --connect qemu:///system \
  --virt-type kvm \
  --name "$vm_name" \
  --memory "$vm_memory" \
  --vcpus 2 \
  --import \
  --os-variant "$os_variant" \
  --disk "path=$instance_dir/disk.qcow2,format=qcow2,bus=virtio" \
  "$@" \
  --network "network=$HF_HIGH_NETWORK_NAME,model=virtio,mac=$guest_mac" \
  --channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0" \
  --graphics "$graphics" \
  --noautoconsole

cleanup_needed=0
trap - EXIT INT TERM
