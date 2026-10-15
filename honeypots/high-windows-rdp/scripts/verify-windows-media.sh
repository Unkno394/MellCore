#!/bin/sh
set -eu
base_iso=${1:?verified Windows ISO}; instance_dir=${2:?instance directory}
for command in xorriso wimlib-imagex; do command -v "$command" >/dev/null; done
mkdir -p "$instance_dir"
wim="$instance_dir/install-media.wim"
trap 'rm -f "$wim"' EXIT INT TERM
if ! xorriso -osirrox on -indev "$base_iso" -extract /sources/install.wim "$wim" >/dev/null 2>&1; then
  xorriso -osirrox on -indev "$base_iso" -extract /sources/install.esd "$wim" >/dev/null 2>&1 || {
    echo 'HF_HIGH_ERROR code=WINDOWS_INSTALL_IMAGE_MISSING stage=inspection: media has neither readable sources/install.wim nor install.esd' >&2
    exit 1
  }
fi
report=$(wimlib-imagex info "$wim" 2)
printf '%s\n' "$report" | grep -Eqi '^Name:[[:space:]]+Windows Server 2022' || {
  echo 'HF_HIGH_ERROR code=WINDOWS_EDITION_UNSUPPORTED stage=inspection: media index 2 is not Windows Server 2022' >&2
  exit 1
}
printf '%s\n' "$report" | grep -Eqi 'Desktop Experience|ServerStandardEval|ServerDatacenterEval' || {
  echo 'HF_HIGH_ERROR code=WINDOWS_EDITION_UNSUPPORTED stage=inspection: media index 2 is not a supported Server 2022 evaluation edition' >&2
  exit 1
}
rm -f "$wim"
trap - EXIT INT TERM
