#!/usr/bin/env bash
set -Eeuo pipefail

image=${1:-honeyforge-pritvoryashka:local}
probe_path=/__hf_missing_config_probe__.json
output=$(docker run --rm --entrypoint /usr/local/bin/pritvoryashka "$image" "$probe_path" 2>&1) || true
if ! grep -Fq 'Error: Read(Os {' <<<"$output" || ! grep -Fq 'No such file or directory' <<<"$output"; then
    printf 'Middle image failed its runtime compatibility check (%s):\n%s\n' "$image" "$output" >&2
    echo 'Rebuild it from the repository Dockerfile; the binary must run against the image glibc.' >&2
    exit 1
fi

echo "Middle image runtime compatibility OK: $image"
