#!/bin/sh
set -eu
instance_id=${1:?instance UUID}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"; vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
timeout_seconds=${HF_HIGH_INSTALL_TIMEOUT_SECONDS:-5400}
case "$timeout_seconds" in ''|*[!0-9]*) echo 'installation timeout must be numeric' >&2; exit 1 ;; esac
[ "$timeout_seconds" -ge 1800 ] && [ "$timeout_seconds" -le 10800 ] || { echo 'installation timeout is outside 1800..10800 seconds' >&2; exit 1; }
record_phase() {
  lifecycle_log=${HF_HIGH_LIFECYCLE_LOG:-$instance_dir/lifecycle-events.jsonl}
  printf '{"event_id":"%s","state":"%s","occurred_at_unix_ms":%s,"detail":null}\n' "$(cat /proc/sys/kernel/random/uuid)" "$1" "$(date +%s%3N)" >> "$lifecycle_log"
  chmod 0600 "$lifecycle_log"
}
wait_rdp() {
  deadline=$(( $(date +%s) + timeout_seconds ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
    if [ -n "$ip" ] && python3 - "$ip" <<'PY'
import socket, sys
try:
    with socket.create_connection((sys.argv[1], 3389), 3): pass
except OSError: raise SystemExit(1)
PY
    then
      printf '%s\n' "$ip" > "$instance_dir/guest-ip"
      return 0
    fi
    sleep 10
  done
  echo 'HF_HIGH_ERROR code=INSTALLATION_READINESS_TIMEOUT stage=installation: Windows Setup did not reach RDP readiness before the timeout' >&2
  return 1
}
[ -f "$instance_dir/installed-disk-verified" ] && exit 0
record_phase INSTALLING
virsh domstate "$vm_name" 2>/dev/null | grep -qi running || virsh start "$vm_name" >/dev/null
wait_rdp
record_phase REBOOTING
virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" && $4 != "-" {print $3}' | while IFS= read -r target; do
  [ -n "$target" ] && virsh change-media "$vm_name" "$target" --eject --live --config >/dev/null
done
virsh destroy "$vm_name" >/dev/null
virsh start "$vm_name" >/dev/null
record_phase CONFIGURING
wait_rdp
umask 077
: > "$instance_dir/installed-disk-verified"
rm -f "$instance_dir/seed.iso" "$instance_dir/Autounattend.xml"
