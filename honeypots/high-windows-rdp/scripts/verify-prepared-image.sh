#!/bin/sh
set -eu

image=${1:?prepared Windows QCOW2 path is required}
checksum_file=$image.sha256
command -v qemu-img >/dev/null
command -v sha256sum >/dev/null
command -v python3 >/dev/null

[ -f "$image" ] && [ ! -L "$image" ] || {
  echo "prepared Windows image is missing or is not a regular file: $image" >&2
  exit 1
}
[ -f "$checksum_file" ] && [ ! -L "$checksum_file" ] || {
  echo "prepared Windows checksum manifest is missing or unsafe: $checksum_file" >&2
  exit 1
}
expected=$(awk 'NR == 1 { print $1 }' "$checksum_file")
printf '%s' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$' || {
  echo 'prepared Windows SHA-256 manifest is invalid' >&2
  exit 1
}
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
actual=$(sha256sum "$image" | awk '{print $1}')
[ "$actual" = "$expected" ] || {
  echo 'prepared Windows image checksum mismatch; refusing a possible live backing image' >&2
  exit 1
}
qemu-img info --output=json "$image" | python3 -c '
import json, sys
info = json.load(sys.stdin)
if info.get("format") != "qcow2":
    raise SystemExit("prepared Windows image is not QCOW2")
if info.get("backing-filename") or info.get("full-backing-filename"):
    raise SystemExit("prepared Windows base image must not have a backing file")
'
qemu-img check -q "$image" || {
  echo 'prepared Windows QCOW2 integrity check failed' >&2
  exit 1
}
