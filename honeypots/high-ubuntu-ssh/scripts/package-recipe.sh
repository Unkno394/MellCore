#!/bin/sh
set -eu

# Creates the High recipe bundle accepted by HF_HIGH_UBUNTU_RECIPE_ARCHIVE for backwards
# compatibility. The historical filename is retained, while the archive contains every supported
# OS adapter so the agent can select one without a second bootstrap operation.
recipe_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:?usage: package-recipe.sh /path/to/hf-high-ubuntu-ssh.tar.gz}
parent_dir=$(dirname "$recipe_dir")
repo_root=$(dirname "$parent_dir")

# macOS otherwise injects AppleDouble `._*` entries that the Linux artifact validator rejects.
# The Windows adapter invokes this administrator-controlled builder on the agent host when its
# immutable prepared image is not cached. Ship only its runtime files, never its tests or caches.
COPYFILE_DISABLE=1 tar -C "$parent_dir" -czf "$output" \
  high-ubuntu-ssh high-debian-ssh high-arch-ssh high-windows-rdp high-custom-iso \
  -C "$repo_root/tools" \
  hf-image-builder/hf-image-builder hf-image-builder/builder.py \
  hf-image-builder/windows-server-2022.pkr.hcl hf-image-builder/templates \
  hf-image-builder/windows
printf '%s\n' "created $output"
