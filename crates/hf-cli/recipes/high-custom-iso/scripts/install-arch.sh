#!/bin/sh
set -eu
instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"; vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
for command in expect openssl base64 python3 virt-cat virsh timeout; do command -v "$command" >/dev/null; done
timeout_seconds=${HF_HIGH_INSTALL_TIMEOUT_SECONDS:-3600}
case "$timeout_seconds" in ''|*[!0-9]*) echo 'installation timeout must be numeric' >&2; exit 1 ;; esac
[ "$timeout_seconds" -ge 900 ] && [ "$timeout_seconds" -le 7200 ] || { echo 'installation timeout is outside 900..7200 seconds' >&2; exit 1; }
boot_timeout_seconds=${HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS:-240}
case "$boot_timeout_seconds" in ''|*[!0-9]*) echo 'Arch serial boot timeout must be numeric' >&2; exit 1 ;; esac
[ "$boot_timeout_seconds" -ge 30 ] && [ "$boot_timeout_seconds" -le 600 ] || { echo 'Arch serial boot timeout is outside 30..600 seconds' >&2; exit 1; }
[ -f "$instance_dir/installed-disk-verified" ] && { virsh domstate "$vm_name" 2>/dev/null | grep -qi running || virsh start "$vm_name" >/dev/null; exit 0; }
record_phase() {
  lifecycle_log=${HF_HIGH_LIFECYCLE_LOG:-$instance_dir/lifecycle-events.jsonl}
  printf '{"event_id":"%s","state":"%s","occurred_at_unix_ms":%s,"detail":null}\n' "$(cat /proc/sys/kernel/random/uuid)" "$1" "$(date +%s%3N)" >> "$lifecycle_log"; chmod 0600 "$lifecycle_log"
}
record_phase INSTALLING
password_file="$instance_dir/ssh-password"
if [ -r "$password_file" ]; then analyst_password=$(cat "$password_file"); else analyst_password=$(openssl rand -base64 24 | tr -d '\n'); umask 077; printf '%s\n' "$analyst_password" > "$password_file"; fi
password_hash=$(printf '%s' "$analyst_password" | openssl passwd -6 -stdin)
hostname="hf-$(printf '%s' "$instance_id" | tr -d '-' | cut -c1-24)"
install_method=legacy
[ ! -r "$instance_dir/arch-install-method" ] || install_method=$(cat "$instance_dir/arch-install-method")
case "$install_method" in
  archinstall) guest_installer="$script_dir/archinstall-guest-install.sh" ;;
  legacy) guest_installer="$script_dir/arch-guest-install.sh" ;;
  *) echo 'HF_HIGH_ERROR code=ARCH_INSTALL_METHOD_INVALID stage=configuration: expected archinstall or legacy' >&2; exit 1 ;;
esac
umask 077
sed -e "s|@@HOSTNAME@@|$hostname|g" -e "s|@@ANALYST_PASSWORD_HASH@@|$password_hash|g" \
  "$guest_installer" > "$instance_dir/arch-guest-install.sh"
chmod 0600 "$instance_dir/arch-guest-install.sh"
grep -q '@@[A-Z0-9_][A-Z0-9_]*@@' "$instance_dir/arch-guest-install.sh" && { echo 'unresolved Arch installer marker' >&2; exit 1; }
payload_file="$instance_dir/arch-guest-install.b64"
console_log="$instance_dir/arch-serial-console.log"
base64 < "$instance_dir/arch-guest-install.sh" | tr -d '\n' > "$payload_file"
: > "$console_log"
chmod 0600 "$payload_file" "$console_log"
cleanup_payload() { rm -f "$payload_file"; }
trap cleanup_payload EXIT HUP INT TERM
already_installed=false
if [ -e "$instance_dir/install-started" ] && virsh domstate "$vm_name" 2>/dev/null | grep -Eqi 'shut|off'; then
  if virt-cat -a "$instance_dir/disk.qcow2" /etc/honeyforge-installed 2>/dev/null | grep -Fx installed >/dev/null; then already_installed=true; else virsh start "$vm_name" >/dev/null; fi
fi
if [ "$already_installed" = false ]; then
  umask 077; : > "$instance_dir/install-started"
  command_timeout=$((timeout_seconds + boot_timeout_seconds + 60))
  HF_HIGH_INSTALL_TIMEOUT_SECONDS=$timeout_seconds \
    HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS=$boot_timeout_seconds \
    timeout "$command_timeout" expect "$script_dir/arch-console.exp" "$vm_name" "$payload_file" "$console_log"
fi
attempt=1; while [ "$attempt" -le 90 ]; do virsh domstate "$vm_name" 2>/dev/null | grep -Eqi 'shut|off' && break; sleep 2; attempt=$((attempt + 1)); done
virsh domstate "$vm_name" 2>/dev/null | grep -Eqi 'shut|off' || {
  echo 'HF_HIGH_ERROR code=ARCH_POWER_OFF_TIMEOUT stage=installation: guest accepted the installer completion sequence but did not power off within 180 seconds; inspect the sanitized serial log' >&2
  exit 1
}
timeout 120 virt-cat -a "$instance_dir/disk.qcow2" /etc/honeyforge-installed 2>/dev/null | grep -Fx installed >/dev/null || {
  echo 'HF_HIGH_ERROR code=ARCH_INSTALL_MARKER_MISSING stage=installation: powered-off target disk lacks the verified installation marker' >&2
  exit 1
}
for boot_file in /boot/vmlinuz-linux /boot/initramfs-linux.img /boot/grub/i386-pc/core.img /boot/grub/grub.cfg; do
  timeout 120 virt-cat -a "$instance_dir/disk.qcow2" "$boot_file" >/dev/null 2>&1 || {
    echo "HF_HIGH_ERROR code=ARCH_BOOT_ARTIFACT_MISSING stage=installation: powered-off target disk lacks $boot_file" >&2
    exit 1
  }
done
record_phase REBOOTING
cdrom_targets=$(virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" { print $3 }')
for cdrom_target in $cdrom_targets; do
  cdrom_source=$(virsh domblklist "$vm_name" --details | awk -v target="$cdrom_target" '$2 == "cdrom" && $3 == target && $4 != "-" { print $4; exit }')
  [ -n "$cdrom_source" ] || continue
  if ! virsh change-media "$vm_name" "$cdrom_target" --eject --config >/dev/null; then
    cdrom_source=$(virsh domblklist "$vm_name" --details | awk -v target="$cdrom_target" '$2 == "cdrom" && $3 == target && $4 != "-" { print $4; exit }')
    [ -z "$cdrom_source" ] || { echo "HF_HIGH_ERROR code=INSTALL_MEDIA_EJECT_FAILED stage=reboot: libvirt failed to eject Arch media from $cdrom_target" >&2; exit 1; }
  fi
done
virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" && $4 != "-" { found=1 } END { exit found }' || {
  echo 'HF_HIGH_ERROR code=INSTALL_MEDIA_EJECT_FAILED stage=reboot: one or more Arch installation media remain attached' >&2
  exit 1
}
umask 077; : > "$instance_dir/installed-disk-verified"
rm -f "$instance_dir/install-started" "$instance_dir/arch-guest-install.sh" "$payload_file"
trap - EXIT HUP INT TERM
virsh start "$vm_name" >/dev/null
record_phase CONFIGURING
