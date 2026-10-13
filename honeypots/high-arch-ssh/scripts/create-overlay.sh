#!/bin/sh
set -eu

base_image=${1:?verified Arch cloud image is required}
instance_dir=${2:?instance directory is required}
instance_id=${3:?instance UUID is required}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
shared_guest_dir=${HF_HIGH_COMMON_GUEST_DIR:-"$script_dir/../../high-ubuntu-ssh/guest"}
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
command -v qemu-img >/dev/null
command -v cloud-localds >/dev/null
command -v openssl >/dev/null
command -v base64 >/dev/null
command -v python3 >/dev/null
[ -r "$base_image" ]
[ -r "$shared_guest_dir/high_telemetry_sensor.py" ]
[ -r "$shared_guest_dir/high_telemetry_audit.py" ]
[ -r "$shared_guest_dir/90-honeyforge.rules" ]
[ -r "$shared_guest_dir/high-telemetry.service" ]
mkdir -p "$instance_dir"
recipe_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
python3 - "$shared_guest_dir/high_telemetry_sensor.py" "$shared_guest_dir/high_telemetry_audit.py" <<'PY'
import pathlib, sys
for filename in sys.argv[1:]:
    compile(pathlib.Path(filename).read_bytes(), filename, "exec")
PY
sensor_b64=$(base64 < "$shared_guest_dir/high_telemetry_sensor.py" | tr -d '\n')
service_b64=$(base64 < "$shared_guest_dir/high-telemetry.service" | tr -d '\n')
audit_sensor_b64=$(base64 < "$shared_guest_dir/high_telemetry_audit.py" | tr -d '\n')
audit_rules_b64=$(base64 < "$shared_guest_dir/90-honeyforge.rules" | tr -d '\n')
password_file="$instance_dir/ssh-password"
if [ -r "$password_file" ]; then analyst_password=$(cat "$password_file"); else analyst_password=$(openssl rand -base64 24 | tr -d '\n'); umask 077; printf '%s\n' "$analyst_password" > "$password_file"; fi
password_hash=$(printf '%s' "$analyst_password" | openssl passwd -6 -stdin)
sed "s|@@INSTANCE_ID@@|$instance_id|g" "$recipe_dir/cloud-init/meta-data" > "$instance_dir/meta-data"
sed \
  -e "s|@@AUDIT_SENSOR_B64@@|$audit_sensor_b64|g" \
  -e "s|@@SENSOR_SERVICE_B64@@|$service_b64|g" \
  -e "s|@@AUDIT_RULES_B64@@|$audit_rules_b64|g" \
  -e "s|@@SENSOR_B64@@|$sensor_b64|g" \
  -e "s|@@ANALYST_PASSWORD_HASH@@|$password_hash|g" \
  "$recipe_dir/cloud-init/user-data" > "$instance_dir/user-data"
if grep -q '@@[A-Z0-9_][A-Z0-9_]*@@' "$instance_dir/meta-data" "$instance_dir/user-data"; then
  echo 'unresolved cloud-init template marker' >&2
  exit 1
fi
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$instance_dir/disk.qcow2" 20G
cloud-localds --network-config="$recipe_dir/cloud-init/network-config" "$instance_dir/seed.iso" "$instance_dir/user-data" "$instance_dir/meta-data"
chmod 0600 "$instance_dir/disk.qcow2" "$instance_dir/seed.iso" "$instance_dir/user-data" "$password_file"
