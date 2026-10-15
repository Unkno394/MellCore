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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
schema_probe=${HF_MIDDLE_SCHEMA_PROBE:-$script_dir/config-schema-probe.json}
if [[ ! -s $schema_probe ]]; then
    repo=$(cd -- "$script_dir/../.." && pwd)
    schema_probe="$repo/honeypots/pritvoryashka/config-schema-probe.json"
fi
[[ -s $schema_probe ]] || { echo "Не найден config schema probe: $schema_probe" >&2; exit 1; }
if schema_output=$(docker run --rm \
    --volume "$schema_probe:/tmp/hf-middle-config-schema-probe.json:ro" \
    --entrypoint /usr/local/bin/pritvoryashka "$image" \
    --check-config /tmp/hf-middle-config-schema-probe.json 2>&1); then
    printf '%s\n' "$schema_output"
else
    printf 'Middle image does not accept the current bait/process config schema (%s):\n%s\n' "$image" "$schema_output" >&2
    echo 'Rebuild Middle from the current pritvoryashka source before updating the agent.' >&2
    exit 1
fi

echo "Middle image runtime and bait/process config schema OK: $image"
