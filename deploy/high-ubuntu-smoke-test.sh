#!/usr/bin/env bash
# Run as root on an Ubuntu VPS with /dev/kvm:
#   sudo bash deploy/high-ubuntu-smoke-test.sh 1488
# This tests the real High VM recipe only. It does not need HoneyForge Center or Agent.
set -Eeuo pipefail

external_port=${1:?usage: high-ubuntu-smoke-test.sh EXTERNAL_SSH_PORT}
case "$external_port" in
  ''|*[!0-9]*) echo "port must be numeric" >&2; exit 2 ;;
esac
(( external_port >= 1 && external_port <= 65535 )) || {
  echo "port must be in 1..65535" >&2
  exit 2
}
[[ $(id -u) -eq 0 ]] || { echo "run this script with sudo" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "KVM is unavailable on this VPS" >&2; exit 1; }

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
recipe="$repo_root/honeypots/high-ubuntu-ssh"
[[ -d "$recipe" ]] || { echo "High recipe not found: $recipe" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils iptables curl
systemctl enable --now libvirtd

image=/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img
sh "$recipe/scripts/download-ubuntu-base-image.sh" "$image"

instance_id=$(cat /proc/sys/kernel/random/uuid)
sh "$recipe/scripts/launch.sh" "$image" "$instance_id" "$external_port"
sh "$recipe/scripts/publish-ssh.sh" "$instance_id" "$external_port"

vm_name="hf-high-$instance_id"
guest_ip=$(virsh domifaddr "$vm_name" --source lease | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1)
password_file="/var/lib/honeyforge/high/$instance_id/ssh-password"
echo
echo "VM is running: $vm_name"
echo "Guest address: $guest_ip"
echo "External port: $external_port"
echo
echo "Waiting for real OpenSSH in the guest..."
for _ in $(seq 1 36); do
  if timeout 2 bash -c "</dev/tcp/$guest_ip/22" 2>/dev/null; then
    echo "Guest OpenSSH is ready."
    break
  fi
  sleep 5
done

if ! timeout 2 bash -c "</dev/tcp/$guest_ip/22" 2>/dev/null; then
  echo "Guest VM started but its SSH did not become ready in 180 seconds." >&2
  echo "Inspect with: virsh console $vm_name" >&2
  exit 1
fi

cat <<EOF

From ANOTHER machine, test the external NAT path:

  ssh -p $external_port analyst@THIS_VPS_PUBLIC_IP

Read this instance's root-only test password on the KVM host:

  sudo cat $password_file

Destroy this exact test VM afterwards:

  sudo HF_HIGH_ROOT=/var/lib/honeyforge/high sh $recipe/scripts/reset.sh $instance_id
EOF
