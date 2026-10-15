#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_dir=${1:-/tmp/mellcore-middle-binary-update-$(date +%Y%m%d-%H%M%S)}
[[ ! -e $artifact_dir ]] || { echo "Каталог уже существует: $artifact_dir" >&2; exit 1; }

echo 'Собираю Middle release-бинарник через Cargo.'
cargo build --locked --release --manifest-path "$repo/Cargo.toml" -p pritvoryashka

install -d -m 0700 "$artifact_dir"
artifact_dir=$(realpath "$artifact_dir")
install -m 0755 "$repo/target/release/pritvoryashka" "$artifact_dir/pritvoryashka"
install -m 0755 "$repo/honeypots/pritvoryashka/docker-entrypoint.sh" "$artifact_dir/docker-entrypoint.sh"
install -m 0644 "$repo/honeypots/pritvoryashka/config-schema-probe.json" "$artifact_dir/config-schema-probe.json"
install -m 0755 "$repo/deploy/vps/update-middle-from-binary-on-agent.sh" "$artifact_dir/update-middle-from-binary-on-agent.sh"
cat > "$artifact_dir/README.txt" <<'EOF'
Обновление Middle image с поддержкой полей baits и virtual_processes.

Перенесите архив на сервер агента, затем выполните от root:

  tar -xzf /tmp/mellcore-middle-binary-update-<timestamp>.tar.gz -C /tmp
  bash /tmp/mellcore-middle-binary-update-<timestamp>/update-middle-from-binary-on-agent.sh \
    /tmp/mellcore-middle-binary-update-<timestamp>

Скрипт соберёт runtime image в Docker агента, проверит конфиг со schema probe,
сохранит текущий образ под rollback-тегом, обновит honeyforge-pritvoryashka:local
и пересоздаст найденные Middle ловушки. Если ловушек сейчас нет, новый образ
останется подготовленным для следующих запусков. Другие образы и сервисы не затрагиваются.
EOF
(cd "$artifact_dir" && sha256sum pritvoryashka docker-entrypoint.sh config-schema-probe.json update-middle-from-binary-on-agent.sh README.txt > SHA256SUMS)
tar -C "$(dirname "$artifact_dir")" -czf "$artifact_dir.tar.gz" "$(basename "$artifact_dir")"

echo "Middle binary: $artifact_dir/pritvoryashka"
echo "Agent update archive: $artifact_dir.tar.gz"
sha256sum "$artifact_dir.tar.gz"
