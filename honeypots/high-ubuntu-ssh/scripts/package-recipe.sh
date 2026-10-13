#!/bin/sh
set -eu

# Creates the High recipe bundle accepted by HF_HIGH_UBUNTU_RECIPE_ARCHIVE for backwards
# compatibility. The historical filename is retained, while the archive contains every supported
# OS adapter so the agent can select one without a second bootstrap operation.
recipe_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:?usage: package-recipe.sh /path/to/hf-high-ubuntu-ssh.tar.gz}
parent_dir=$(dirname "$recipe_dir")

# macOS otherwise injects AppleDouble `._*` entries that the Linux artifact validator rejects.
COPYFILE_DISABLE=1 tar -C "$parent_dir" -czf "$output" high-ubuntu-ssh high-arch-ssh high-windows-rdp
printf '%s\n' "created $output"
