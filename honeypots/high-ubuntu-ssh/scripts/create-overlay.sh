#!/bin/sh
set -eu
base_image=${1:?path to verified Ubuntu cloud base image is required}
instance_dir=${2:?instance directory is required}
instance_id=${3:?instance id is required}
command -v qemu-img >/dev/null
command -v cloud-localds >/dev/null
command -v base64 >/dev/null
[ -r "$base_image" ]
mkdir -p "$instance_dir"
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$instance_dir/disk.qcow2" 20G
recipe_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sensor_b64=$(base64 < "$recipe_dir/guest/high_telemetry_sensor.py" | tr -d '\n')
service_b64=$(base64 < "$recipe_dir/guest/high-telemetry.service" | tr -d '\n')
audit_sensor_b64=$(base64 < "$recipe_dir/guest/high_telemetry_audit.py" | tr -d '\n')
audit_rules_b64=$(base64 < "$recipe_dir/guest/90-honeyforge.rules" | tr -d '\n')
sed "s/INSTANCE_ID/$instance_id/g" "$recipe_dir/cloud-init/meta-data" > "$instance_dir/meta-data"
sed \
  -e "s|SENSOR_B64|$sensor_b64|g" \
  -e "s|SENSOR_SERVICE_B64|$service_b64|g" \
  -e "s|AUDIT_SENSOR_B64|$audit_sensor_b64|g" \
  -e "s|AUDIT_RULES_B64|$audit_rules_b64|g" \
  "$recipe_dir/cloud-init/user-data" > "$instance_dir/user-data"
cloud-localds --network-config="$recipe_dir/cloud-init/network-config" "$instance_dir/seed.iso" "$instance_dir/user-data" "$instance_dir/meta-data"
chmod 0600 "$instance_dir/disk.qcow2" "$instance_dir/seed.iso" "$instance_dir/user-data"
