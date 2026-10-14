#!/bin/sh
set -eu

image=${1:?prepared Windows QCOW2 path is required}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
manifest=$image.sha256

if [ -e "$image" ] || [ -e "$manifest" ]; then
  [ -f "$image" ] && [ -f "$manifest" ] || {
    echo 'incomplete prepared Windows image publication; refusing rebuild or replacement' >&2
    exit 1
  }
  exec sh "$script_dir/verify-prepared-image.sh" "$image"
fi

builder=${HF_HIGH_IMAGE_BUILDER:-/usr/local/lib/honeyforge/hf-image-builder/hf-image-builder}
catalog=${HF_HIGH_WINDOWS_SOURCE_CATALOG:-/etc/honeyforge/image-sources/windows-server-2022.json}
[ -x "$builder" ] || {
  echo "hf-image-builder is not installed or executable: $builder" >&2
  exit 1
}
[ -f "$catalog" ] && [ ! -L "$catalog" ] || {
  echo "approved Windows source catalog is missing or unsafe: $catalog; run hf-image-builder register-sources once as administrator" >&2
  exit 1
}

"$builder" --catalog "$catalog" build
exec sh "$script_dir/verify-prepared-image.sh" "$image"
