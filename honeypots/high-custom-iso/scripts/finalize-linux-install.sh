#!/bin/sh
set -eu
instance_id=${1:?instance UUID}; flavor=${2:?installer flavor}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"; vm_name="hf-high-$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
case "$flavor" in ubuntu|debian) ;; *) echo "unsupported finalizer flavor: $flavor" >&2; exit 1 ;; esac
for command in virsh python3; do command -v "$command" >/dev/null; done
[ "$flavor" != ubuntu ] || { command -v virt-cat >/dev/null; command -v timeout >/dev/null; }
timeout_seconds=${HF_HIGH_INSTALL_TIMEOUT_SECONDS:-3600}
ready_timeout_seconds=${HF_HIGH_READY_TIMEOUT_SECONDS:-300}
case "$timeout_seconds" in ''|*[!0-9]*) echo 'installation timeout must be numeric' >&2; exit 1 ;; esac
case "$ready_timeout_seconds" in ''|*[!0-9]*) echo 'readiness timeout must be numeric' >&2; exit 1 ;; esac
[ "$timeout_seconds" -ge 900 ] && [ "$timeout_seconds" -le 7200 ] || { echo 'installation timeout is outside 900..7200 seconds' >&2; exit 1; }
[ "$ready_timeout_seconds" -ge 60 ] && [ "$ready_timeout_seconds" -le 900 ] || { echo 'readiness timeout is outside 60..900 seconds' >&2; exit 1; }
record_phase() {
  lifecycle_log=${HF_HIGH_LIFECYCLE_LOG:-$instance_dir/lifecycle-events.jsonl}
  mkdir -p "$(dirname "$lifecycle_log")"
  printf '{"event_id":"%s","state":"%s","occurred_at_unix_ms":%s,"detail":null}\n' "$(cat /proc/sys/kernel/random/uuid)" "$1" "$(date +%s%3N)" >> "$lifecycle_log"
  chmod 0600 "$lifecycle_log"
}
legacy_wait_ready() {
  deadline=$(( $(date +%s) + timeout_seconds ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
    if [ -n "$ip" ] && virsh qemu-agent-command "$vm_name" '{"execute":"guest-ping"}' >/dev/null 2>&1 && \
      python3 - "$ip" <<'PY'
import socket, sys
try:
    with socket.create_connection((sys.argv[1], 22), 2): pass
except OSError: raise SystemExit(1)
PY
    then printf '%s\n' "$ip" > "$instance_dir/guest-ip"; return 0; fi
    sleep 5
  done
  echo "HF_HIGH_ERROR code=INSTALLATION_READINESS_TIMEOUT stage=installation: $flavor did not reach SSH plus qemu-guest-agent readiness" >&2; return 1
}
if [ "$flavor" = debian ]; then
  [ -f "$instance_dir/installed-disk-verified" ] && exit 0
  record_phase INSTALLING
  virsh domstate "$vm_name" 2>/dev/null | grep -qi running || virsh start "$vm_name" >/dev/null
  legacy_wait_ready
  record_phase REBOOTING
  target=$(virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" && $4 != "-" { print $3; exit }')
  if [ -n "$target" ]; then virsh change-media "$vm_name" "$target" --eject --live --config >/dev/null; fi
  virsh destroy "$vm_name" >/dev/null
  virsh start "$vm_name" >/dev/null
  record_phase CONFIGURING
  legacy_wait_ready
  umask 077; : > "$instance_dir/installed-disk-verified"
  rm -rf "$instance_dir/iso-payload" "$instance_dir/unattended.iso" "$instance_dir/grub.cfg" "$instance_dir/preseed.cfg"
  exit 0
fi
domain_state() { virsh domstate "$vm_name" 2>/dev/null | tr '[:upper:]' '[:lower:]'; }
disk_marker_ready() {
  timeout 120 virt-cat -a "$instance_dir/disk.qcow2" /etc/honeyforge-installed 2>/dev/null | grep -Fx installed >/dev/null
}
cdrom_target() { virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" { print $3; exit }'; }
cdrom_source() { virsh domblklist "$vm_name" --details | awk '$2 == "cdrom" && $4 != "-" { print $4; exit }'; }
eject_install_media() {
  target=$(cdrom_target)
  [ -n "$target" ] || { echo 'HF_HIGH_ERROR code=INSTALL_MEDIA_DEVICE_MISSING stage=reboot: installer CD-ROM device is absent' >&2; return 1; }
  # The installer or libvirt may already have emptied the tray after the earlier source probe.
  # Re-check immediately before mutation; an empty drive is the requested final state.
  [ -n "$(cdrom_source)" ] || return 0
  if virsh change-media "$vm_name" "$target" --eject --config >/dev/null; then return 0; fi
  # Suppress only the race where libvirt reports failure after another actor completed the eject.
  [ -z "$(cdrom_source)" ] && return 0
  echo 'HF_HIGH_ERROR code=INSTALL_MEDIA_EJECT_FAILED stage=reboot: libvirt failed to eject installation media and the CD-ROM is still populated' >&2
  return 1
}
wait_for_installer_poweroff() {
  deadline=$(( $(date +%s) + timeout_seconds ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    state=$(domain_state)
    case "$state" in
      *shut*|*off*)
        disk_marker_ready || {
          echo "HF_HIGH_ERROR code=INSTALLATION_TARGET_INVALID stage=installation: $flavor powered off without the installed-system marker" >&2
          return 1
        }
        return 0
        ;;
      *crash*)
        echo "HF_HIGH_ERROR code=INSTALLATION_VM_CRASHED stage=installation: $flavor installer VM crashed" >&2
        return 1
        ;;
    esac
    sleep 5
  done
  echo "HF_HIGH_ERROR code=INSTALLATION_TIMEOUT stage=installation: $flavor did not finish and power off within ${timeout_seconds}s" >&2
  return 1
}
guest_checks() {
  ip=$1
  python3 - "$vm_name" "$ip" <<'PY'
import json, socket, subprocess, sys, time

name, address = sys.argv[1:]

def agent(request):
    try:
        completed = subprocess.run(
            ["virsh", "qemu-agent-command", name, json.dumps(request, separators=(",", ":"))],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, text=True, timeout=3,
        )
    except subprocess.TimeoutExpired:
        return None
    if completed.returncode:
        return None
    try:
        reply = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return None if "error" in reply else reply.get("return")

if agent({"execute": "guest-ping"}) is None:
    raise SystemExit(1)

def guest_exec(path, arguments):
    result = agent({"execute": "guest-exec", "arguments": {
        "path": path, "arg": arguments, "capture-output": True,
    }})
    if not isinstance(result, dict) or not isinstance(result.get("pid"), int):
        return False
    for _ in range(20):
        status = agent({"execute": "guest-exec-status", "arguments": {"pid": result["pid"]}})
        if isinstance(status, dict) and status.get("exited"):
            return status.get("exitcode") == 0
        time.sleep(0.1)
    return False

if not guest_exec("/usr/bin/grep", ["-Fxq", "installed", "/etc/honeyforge-installed"]):
    raise SystemExit(1)
if not guest_exec("/bin/systemctl", ["is-active", "--quiet", "ssh.service", "qemu-guest-agent.service", "high-telemetry.service"]):
    raise SystemExit(1)
try:
    with socket.create_connection((address, 22), 2) as connection:
        connection.settimeout(2)
        banner = connection.recv(255)
except OSError:
    raise SystemExit(1)
if not (banner.startswith(b"SSH-2.0-") or banner.startswith(b"SSH-1.99-")):
    raise SystemExit(1)
PY
}
wait_installed_ready() {
  deadline=$(( $(date +%s) + ready_timeout_seconds ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    ip=$(virsh domifaddr "$vm_name" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1 || true)
    if [ -n "$ip" ] && guest_checks "$ip"; then
      temporary=$(mktemp "$instance_dir/.guest-ip.XXXXXX")
      printf '%s\n' "$ip" > "$temporary"; chmod 0600 "$temporary"; mv "$temporary" "$instance_dir/guest-ip"
      return 0
    fi
    sleep 5
  done
  echo "HF_HIGH_ERROR code=INSTALLED_GUEST_READINESS_TIMEOUT stage=readiness: installed $flavor did not provide SSH, qemu-guest-agent, guest marker and telemetry within ${ready_timeout_seconds}s" >&2
  return 1
}

[ -f "$instance_dir/installed-disk-verified" ] && exit 0
source=$(cdrom_source)
if [ -n "$source" ]; then
  record_phase INSTALLING
  state=$(domain_state)
  case "$state" in
    *shut*|*off*) disk_marker_ready || virsh start "$vm_name" >/dev/null ;;
  esac
  wait_for_installer_poweroff
  record_phase REBOOTING
  eject_install_media
else
  record_phase REBOOTING
  state=$(domain_state)
  case "$state" in *shut*|*off*) disk_marker_ready || { echo 'HF_HIGH_ERROR code=INSTALLATION_TARGET_INVALID stage=installation: installed-system marker is absent from disk' >&2; exit 1; } ;; esac
fi
state=$(domain_state)
case "$state" in *running*|*idle*) ;; *) virsh start "$vm_name" >/dev/null ;; esac
record_phase CONFIGURING
wait_installed_ready
umask 077; : > "$instance_dir/installed-disk-verified"
rm -rf "$instance_dir/iso-payload" "$instance_dir/unattended.iso" "$instance_dir/grub.cfg" "$instance_dir/preseed.cfg"
