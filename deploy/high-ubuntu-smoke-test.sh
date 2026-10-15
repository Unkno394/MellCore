#!/usr/bin/env bash
# Run as root on an Ubuntu VPS. KVM is the default; set HF_HIGH_ACCELERATION=tcg
# for isolated functional testing only (TCG does not provide a trusted guest boundary).
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
acceleration=${HF_HIGH_ACCELERATION:-auto}
case "$acceleration" in
  auto|kvm)
    [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
      echo "KVM is unavailable; set HF_HIGH_ACCELERATION=tcg only for an isolated test" >&2
      exit 1
    }
    export HF_HIGH_VIRT_TYPE=kvm
    export HF_HIGH_ROOT=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}
    ;;
  tcg)
    export HF_HIGH_VIRT_TYPE=qemu
    HF_HIGH_ROOT=${HF_HIGH_ROOT:-/var/lib/honeyforge-tcg-test}
    [[ "$HF_HIGH_ROOT" == /* && "$HF_HIGH_ROOT" != / ]] || {
      echo "TCG tests require an absolute, dedicated HF_HIGH_ROOT" >&2
      exit 2
    }
    HF_HIGH_ROOT=$(realpath -m -- "$HF_HIGH_ROOT")
    production_state=$(realpath -m -- /var/lib/honeyforge)
    case "$HF_HIGH_ROOT/" in
      "$production_state/"*)
        echo "TCG test state must be outside the production /var/lib/honeyforge tree" >&2
        exit 2
        ;;
    esac
    [[ "$HF_HIGH_ROOT" != / ]] || { echo "TCG test state cannot be /" >&2; exit 2; }
    install -d -m 0700 -- "$HF_HIGH_ROOT"
    export HF_HIGH_ROOT
    ;;
  *) echo "HF_HIGH_ACCELERATION must be auto, kvm, or tcg" >&2; exit 2 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
recipe="$repo_root/honeypots/high-ubuntu-ssh"
[[ -d "$recipe" ]] || { echo "High recipe not found: $recipe" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients virtinst cloud-image-utils iptables curl
systemctl enable --now libvirtd

image=/var/lib/honeyforge/images/noble-server-cloudimg-amd64.img
sh "$recipe/scripts/download-ubuntu-base-image.sh" "$image"

instance_id=$(cat /proc/sys/kernel/random/uuid)
sh "$recipe/scripts/launch.sh" "$image" "$instance_id" "$external_port"
if [[ "$HF_HIGH_VIRT_TYPE" == kvm ]]; then
  sh "$recipe/scripts/publish-ssh.sh" "$instance_id" "$external_port"
fi

vm_name="hf-high-$instance_id"
guest_ip=
for _ in $(seq 1 180); do
  guest_ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
  [[ -n "$guest_ip" ]] && break
  sleep 5
done
[[ -n "$guest_ip" ]] || { echo "Guest did not obtain an isolated DHCP lease" >&2; exit 1; }
password_file="$HF_HIGH_ROOT/$instance_id/ssh-password"
echo
echo "VM is running: $vm_name"
echo "Guest address: $guest_ip"
if [[ "$HF_HIGH_VIRT_TYPE" == kvm ]]; then
  echo "External port: $external_port"
else
  echo "External publication: disabled (TCG test mode; connect to the private guest IP from this host)"
fi
echo
echo "Waiting for real OpenSSH in the guest..."
readiness_attempts=36
[[ "$HF_HIGH_VIRT_TYPE" == qemu ]] && readiness_attempts=180
for _ in $(seq 1 "$readiness_attempts"); do
  if timeout 2 bash -c "</dev/tcp/$guest_ip/22" 2>/dev/null; then
    echo "Guest OpenSSH is ready."
    break
  fi
  sleep 5
done

if ! timeout 2 bash -c "</dev/tcp/$guest_ip/22" 2>/dev/null; then
  echo "Guest VM started but its SSH did not become ready after $readiness_attempts attempts." >&2
  echo "Inspect with: virsh console $vm_name" >&2
  exit 1
fi

if [[ "$HF_HIGH_VIRT_TYPE" == kvm ]]; then
  cat <<EOF

From another machine, test the external NAT path:

  ssh -p $external_port analyst@THIS_VPS_PUBLIC_IP
EOF
else
  cat <<EOF

TCG test mode does not publish SSH. Connect from this VPS to the private guest address:

  ssh analyst@$guest_ip
EOF
fi
printf '\nRead this instance\x27s root-only test password on the host:\n\n  sudo cat %q\n\n' "$password_file"
printf 'Remove this exact test VM and its state:\n\n  sudo env HF_HIGH_ROOT=%q sh %q %q\n' \
  "$HF_HIGH_ROOT" "$recipe/scripts/reset.sh" "$instance_id"
