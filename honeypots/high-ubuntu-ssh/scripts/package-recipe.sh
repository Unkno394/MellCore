#!/bin/sh
set -eu

# Creates the exact archive accepted by HF_HIGH_UBUNTU_RECIPE_ARCHIVE.
# Run from any directory; the archive contains one top-level high-ubuntu-ssh directory.
recipe_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:?usage: package-recipe.sh /path/to/hf-high-ubuntu-ssh.tar.gz}
parent_dir=$(dirname "$recipe_dir")

tar -C "$parent_dir" -czf "$output" high-ubuntu-ssh
printf '%s\n' "created $output"
