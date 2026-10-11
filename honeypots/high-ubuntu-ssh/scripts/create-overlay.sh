#!/bin/sh
set -eu
base_image=${1:?path to verified Ubuntu cloud base image is required}
instance_dir=${2:?instance directory is required}
instance_id=${3:?instance id is required}
command -v qemu-img >/dev/null
command -v cloud-localds >/dev/null
[ -r "$base_image" ]
mkdir -p "$instance_dir"
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$instance_dir/disk.qcow2" 20G
sed "s/INSTANCE_ID/$instance_id/g" "$(dirname "$0")/../cloud-init/meta-data" > "$instance_dir/meta-data"
cloud-localds --network-config="$(dirname "$0")/../cloud-init/network-config" "$instance_dir/seed.iso" "$(dirname "$0")/../cloud-init/user-data" "$instance_dir/meta-data"
chmod 0600 "$instance_dir/disk.qcow2" "$instance_dir/seed.iso"
