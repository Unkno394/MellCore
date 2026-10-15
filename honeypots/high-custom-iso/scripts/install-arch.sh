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
shared_guest_dir="$script_dir/../../high-ubuntu-ssh/guest"
python3 - "$shared_guest_dir/high_telemetry_sensor.py" "$shared_guest_dir/high_telemetry_audit.py" <<'PY'
import pathlib, sys
for filename in sys.argv[1:]: compile(pathlib.Path(filename).read_bytes(), filename, "exec")
PY
sensor_b64=$(base64 < "$shared_guest_dir/high_telemetry_sensor.py" | tr -d '\n')
audit_sensor_b64=$(base64 < "$shared_guest_dir/high_telemetry_audit.py" | tr -d '\n')
service_b64=$(base64 < "$shared_guest_dir/high-telemetry.service" | tr -d '\n')
audit_rules_b64=$(base64 < "$shared_guest_dir/90-honeyforge.rules" | tr -d '\n')
sed -e "s|@@HOSTNAME@@|$hostname|g" -e "s|@@ANALYST_PASSWORD_HASH@@|$password_hash|g" \
  -e "s|@@AUDIT_SENSOR_B64@@|$audit_sensor_b64|g" -e "s|@@SERVICE_B64@@|$service_b64|g" \
  -e "s|@@AUDIT_RULES_B64@@|$audit_rules_b64|g" -e "s|@@SENSOR_B64@@|$sensor_b64|g" \
  "$script_dir/arch-guest-install.sh" > "$instance_dir/arch-guest-install.sh"
grep -q '@@[A-Z0-9_][A-Z0-9_]*@@' "$instance_dir/arch-guest-install.sh" && { echo 'unresolved Arch installer marker' >&2; exit 1; }
payload=$(base64 < "$instance_dir/arch-guest-install.sh" | tr -d '\n')
already_installed=false
if [ -e "$instance_dir/install-started" ] && virsh domstate "$vm_name" 2>/dev/null | grep -Eqi 'shut|off'; then
  if virt-cat -a "$instance_dir/disk.qcow2" /etc/honeyforge-installed 2>/dev/null | grep -Fx installed >/dev/null; then already_installed=true; else virsh start "$vm_name" >/dev/null; fi
fi
if [ "$already_installed" = false ]; then
  umask 077; : > "$instance_dir/install-started"
  HF_HIGH_INSTALL_TIMEOUT_SECONDS=$timeout_seconds timeout "$timeout_seconds" expect "$script_dir/arch-console.exp" "$vm_name" "$payload"
fi
attempt=1; while [ "$attempt" -le 90 ]; do virsh domstate "$vm_name" 2>/dev/null | grep -Eqi 'shut|off' && break; sleep 2; attempt=$((attempt + 1)); done
virsh domstate "$vm_name" 2>/dev/null | grep -Eqi 'shut|off' || { echo 'installed Arch did not power off' >&2; exit 1; }
virt-cat -a "$instance_dir/disk.qcow2" /etc/honeyforge-installed | grep -Fx installed >/dev/null || { echo 'Arch installation marker is absent from target disk' >&2; exit 1; }
record_phase REBOOTING
cdrom_target=$(virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" { print $3; exit }')
cdrom_source=$(virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" && $4 != "-" { print $4; exit }')
if [ -n "$cdrom_source" ]; then
  [ -n "$cdrom_target" ] || { echo 'HF_HIGH_ERROR code=INSTALL_MEDIA_DEVICE_MISSING stage=reboot: installer CD-ROM device is absent' >&2; exit 1; }
  if ! virsh change-media "$vm_name" "$cdrom_target" --eject --config >/dev/null; then
    cdrom_source=$(virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" && $4 != "-" { print $4; exit }')
    [ -z "$cdrom_source" ] || { echo 'HF_HIGH_ERROR code=INSTALL_MEDIA_EJECT_FAILED stage=reboot: libvirt failed to eject Arch installation media' >&2; exit 1; }
  fi
fi
umask 077; : > "$instance_dir/installed-disk-verified"
rm -f "$instance_dir/install-started" "$instance_dir/arch-guest-install.sh"
virsh start "$vm_name" >/dev/null
record_phase CONFIGURING
