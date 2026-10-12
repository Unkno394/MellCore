#!/bin/sh
set -eu

base_image=${1:?usage: prepare-image.sh BASE_QCOW2 OUTPUT_QCOW2 BUNDLE_DIRECTORY}
output_image=${2:?usage: prepare-image.sh BASE_QCOW2 OUTPUT_QCOW2 BUNDLE_DIRECTORY}
bundle_dir=${3:?usage: prepare-image.sh BASE_QCOW2 OUTPUT_QCOW2 BUNDLE_DIRECTORY}
command -v qemu-img >/dev/null
command -v virt-customize >/dev/null
command -v sha256sum >/dev/null
[ -r "$base_image" ]
[ -r "$bundle_dir/SHA256SUMS" ]
[ -r "$bundle_dir/VERSIONS" ]

bundle_dir=$(CDPATH= cd -- "$bundle_dir" && pwd)
(cd "$bundle_dir" && sha256sum -c SHA256SUMS)

mkdir -p "$(dirname "$output_image")"
temporary="$output_image.tmp"
trap 'rm -f "$temporary"' EXIT INT TERM
qemu-img convert -f qcow2 -O qcow2 "$base_image" "$temporary"

bundle_name=$(basename "$bundle_dir")
virt-customize -a "$temporary" \
  --mkdir /opt/honeyforge-offline \
  --copy-in "$bundle_dir:/opt/honeyforge-offline" \
  --run-command "cd /opt/honeyforge-offline/$bundle_name && sha256sum -c SHA256SUMS" \
  --run-command "dpkg -i /opt/honeyforge-offline/$bundle_name/*.deb || true" \
  --run-command "dpkg -i /opt/honeyforge-offline/$bundle_name/*.deb" \
  --run-command 'command -v auditctl && command -v augenrules && command -v qemu-ga && command -v python3 && command -v sshd' \
  --run-command 'systemctl enable auditd qemu-guest-agent ssh'

qemu-img check "$temporary"
chmod 0600 "$temporary"
mv "$temporary" "$output_image"
trap - EXIT INT TERM
sha256sum "$output_image" > "$output_image.sha256"
printf '%s\n' "prepared offline High image: $output_image"
