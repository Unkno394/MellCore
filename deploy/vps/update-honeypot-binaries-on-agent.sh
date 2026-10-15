#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

bundle_dir=${1:-/tmp/hf-honeypot-update}
state_dir=${HF_STATE_DIR:-}
trap_root=${HF_TRAP_ROOT:-}
if [[ -r /etc/honeyforge/agent.env ]]; then
    if [[ -z $state_dir ]]; then
        state_dir=$(awk -F= '$1 == "HF_STATE_DIR" { sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' /etc/honeyforge/agent.env)
    fi
    if [[ -z $trap_root ]]; then
        trap_root=$(awk -F= '$1 == "HF_TRAP_ROOT" { sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' /etc/honeyforge/agent.env)
    fi
fi
state_dir=${state_dir:-/var/lib/honeyforge}
trap_root=${trap_root:-$state_dir/traps}
export HF_STATE_DIR=$state_dir HF_TRAP_ROOT=$trap_root
low_image=honeyforge-low:local
middle_image=honeyforge-pritvoryashka:local

[[ $EUID -eq 0 ]] || { echo 'Запусти скрипт от root на сервере агента.' >&2; exit 1; }
[[ -d $bundle_dir ]] || { echo "Не найден каталог артефактов: $bundle_dir" >&2; exit 1; }
bundle_dir=$(realpath "$bundle_dir")
for file in hf-agent honeyforge-low pritvoryashka docker-entrypoint.sh config-schema-probe.json; do
    [[ -s $bundle_dir/$file ]] || { echo "Не найден файл: $bundle_dir/$file" >&2; exit 1; }
done
command -v docker >/dev/null 2>&1 || { echo 'Не найден Docker.' >&2; exit 1; }
docker info >/dev/null
[[ -d $trap_root ]] || { echo "Не найден каталог ловушек агента: $trap_root" >&2; exit 1; }

if [[ -s $bundle_dir/SHA256SUMS ]]; then
    (cd "$bundle_dir" && sha256sum --check SHA256SUMS)
fi
if ! "$bundle_dir/hf-agent" --help >/dev/null 2>&1; then
    echo 'Новый hf-agent не запускается на этой ОС; бинарник и контейнеры не заменялись.' >&2
    exit 1
fi

low_compose=()
middle_compose=()
while IFS= read -r -d '' compose; do
    if grep -Fq "image: $low_image" "$compose"; then
        low_compose+=("$compose")
    fi
    if grep -Fq "image: $middle_image" "$compose"; then
        middle_compose+=("$compose")
    fi
done < <(find "$trap_root" -mindepth 2 -maxdepth 2 -type f -name compose.yaml -print0)

if (( ${#low_compose[@]} + ${#middle_compose[@]} == 0 )); then
    echo "Активных Low/Middle ловушек в $trap_root нет; образы будут обновлены для следующих ловушек."
fi

work_dir=$(mktemp -d /tmp/hf-honeypot-image-update.XXXXXX)
low_build_image=
middle_build_image=
cleanup() {
    docker image rm "$low_build_image" "$middle_build_image" >/dev/null 2>&1 || true
    rm -rf "$work_dir"
}
trap cleanup EXIT

low_context=$work_dir/low
middle_context=$work_dir/middle
mkdir -p "$low_context/config" "$middle_context"
install -m 0755 "$bundle_dir/honeyforge-low" "$low_context/honeyforge-low"
install -m 0755 "$bundle_dir/pritvoryashka" "$middle_context/pritvoryashka"
install -m 0755 "$bundle_dir/docker-entrypoint.sh" "$middle_context/docker-entrypoint.sh"
install -m 0644 "$bundle_dir/config-schema-probe.json" "$middle_context/config-schema-probe.json"

cat > "$low_context/config/docker.json" <<'JSON'
{
  "bind_address": "0.0.0.0",
  "port": 2222,
  "banner": "SSH-2.0-OpenSSH_9.6",
  "trap_id": "9a8a8262-556b-43c4-a73f-736c32556721"
}
JSON

cat > "$low_context/Dockerfile" <<'DOCKERFILE'
FROM debian:bookworm-slim
COPY honeyforge-low /usr/local/bin/honeyforge-low
COPY config/docker.json /etc/honeyforge/config.json
USER 65532:65532
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/honeyforge-low"]
CMD ["--config", "/etc/honeyforge/config.json"]
DOCKERFILE

cat > "$middle_context/Dockerfile" <<'DOCKERFILE'
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates wget \
    && wget -q https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb \
    && dpkg -i /tmp/packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends powershell \
    && rm -f /tmp/packages-microsoft-prod.deb \
    && rm -rf /var/lib/apt/lists/*
COPY pritvoryashka /usr/local/bin/pritvoryashka
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY config-schema-probe.json /tmp/hf-middle-config-schema-probe.json
RUN chmod 0755 /usr/local/bin/pritvoryashka /usr/local/bin/docker-entrypoint \
    && output="$(/usr/local/bin/pritvoryashka /__hf_missing_config_probe__.json 2>&1 || true)" \
    && printf '%s\n' "$output" | grep -Fq 'Error: Read(Os {' \
    && printf '%s\n' "$output" | grep -Fq 'No such file or directory' || \
       { printf 'Middle binary did not start in Debian Trixie:\n%s\n' "$output" >&2; exit 1; }
RUN /usr/local/bin/pritvoryashka --check-config /tmp/hf-middle-config-schema-probe.json \
    && /usr/local/bin/pritvoryashka --check-windows-parser \
    && rm -f /tmp/hf-middle-config-schema-probe.json
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["/etc/honeyforge/pritvoryashka.json"]
DOCKERFILE

stamp=$(date +%Y%m%d%H%M%S)
low_build_image="honeyforge-low:binary-update-$stamp"
middle_build_image="honeyforge-pritvoryashka:binary-update-$stamp"

echo 'Собираю runtime-образы из готовых бинарников; Cargo/Rust не запускаются.'
docker build --file "$low_context/Dockerfile" --tag "$low_build_image" "$low_context"
docker build --file "$middle_context/Dockerfile" --tag "$middle_build_image" "$middle_context"

low_user=$(docker image inspect --format '{{.Config.User}}' "$low_build_image")
[[ $low_user == '65532:65532' ]] || {
    echo "Неверный пользователь Low image: $low_user" >&2
    exit 1
}
middle_probe=$(docker run --rm --entrypoint /usr/local/bin/pritvoryashka \
    "$middle_build_image" /__hf_missing_config_probe__.json 2>&1 || true)
if ! grep -Fq 'Error: Read(Os {' <<<"$middle_probe" \
    || ! grep -Fq 'No such file or directory' <<<"$middle_probe"; then
    printf 'Middle image не прошёл проверку запуска в runtime:\n%s\n' "$middle_probe" >&2
    exit 1
fi
if middle_schema_probe=$(docker run --rm \
    --volume "$bundle_dir/config-schema-probe.json:/tmp/hf-middle-config-schema-probe.json:ro" \
    --entrypoint /usr/local/bin/pritvoryashka "$middle_build_image" \
    --check-config /tmp/hf-middle-config-schema-probe.json 2>&1); then
    printf '%s\n' "$middle_schema_probe"
else
    printf 'Middle image не принимает схему baits/virtual_processes:\n%s\n' "$middle_schema_probe" >&2
    exit 1
fi

old_low_id=$(docker image inspect --format '{{.Id}}' "$low_image" 2>/dev/null || true)
old_middle_id=$(docker image inspect --format '{{.Id}}' "$middle_image" 2>/dev/null || true)
if [[ -n $old_low_id ]]; then
    docker tag "$old_low_id" "honeyforge-low:rollback-$stamp"
    echo "Старый Low сохранён как honeyforge-low:rollback-$stamp"
fi
if [[ -n $old_middle_id ]]; then
    docker tag "$old_middle_id" "honeyforge-pritvoryashka:rollback-$stamp"
    echo "Старый Middle сохранён как honeyforge-pritvoryashka:rollback-$stamp"
fi
docker tag "$low_build_image" "$low_image"
docker tag "$middle_build_image" "$middle_image"

failed=0
recreate_and_report() {
    local compose=$1
    local project trap_id container_id state
    trap_id=$(basename -- "$(dirname -- "$compose")")
    project="hf-${trap_id//-/}"
    echo "Пересоздаю $compose"
    if ! docker compose --project-name "$project" --file "$compose" up -d --force-recreate; then
        failed=1
        return
    fi
    container_id=$(docker compose --project-name "$project" --file "$compose" ps --all -q honeypot | head -n 1)
    if [[ -z $container_id ]]; then
        echo "Контейнер honeypot не найден после запуска: $compose" >&2
        failed=1
        return
    fi
    sleep 2
    state=$(docker inspect --format '{{.State.Status}}' "$container_id")
    docker ps -a --filter "id=$container_id" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}'
    echo "Свежие логи: $compose"
    docker logs --tail 50 --timestamps "$container_id" 2>&1 || true
    if [[ $state != running ]]; then
        echo "Контейнер не в состоянии running: $state ($compose)" >&2
        failed=1
    fi
}

for compose in "${low_compose[@]}"; do recreate_and_report "$compose"; done
for compose in "${middle_compose[@]}"; do recreate_and_report "$compose"; done

if (( failed )); then
    echo 'Обновление образов выполнено, но проверка одного или нескольких контейнеров не прошла.' >&2
    echo 'Старые образы сохранены под rollback-тегами, указанными выше.' >&2
    exit 1
fi

agent_backup="/usr/local/bin/hf-agent.rollback-$stamp"
if [[ -e /usr/local/bin/hf-agent ]]; then
    cp -a /usr/local/bin/hf-agent "$agent_backup"
fi
install -m 0755 "$bundle_dir/hf-agent" /usr/local/bin/.hf-agent.new
mv -f /usr/local/bin/.hf-agent.new /usr/local/bin/hf-agent

rollback_agent() {
    if [[ -e $agent_backup ]]; then
        install -m 0755 "$agent_backup" /usr/local/bin/.hf-agent.rollback-new
        mv -f /usr/local/bin/.hf-agent.rollback-new /usr/local/bin/hf-agent
        systemctl restart hf-agent.service >/dev/null 2>&1 || true
    fi
}

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl restart hf-agent.service || ! systemctl is-active --quiet hf-agent.service; then
        echo 'Новый hf-agent не запустился; возвращаю прежний бинарник.' >&2
        rollback_agent
        systemctl status hf-agent.service --no-pager -l || true
        exit 1
    fi
    systemctl status hf-agent.service --no-pager -l || true
    journalctl -u hf-agent.service -n 30 --no-pager || true
elif command -v rc-service >/dev/null 2>&1; then
    if ! rc-service hf-agent restart; then
        echo 'Новый hf-agent не запустился; возвращаю прежний бинарник.' >&2
        rollback_agent
        exit 1
    fi
    rc-service hf-agent status || true
else
    echo 'Образы ловушек обновлены, но systemd/OpenRC не найдены для перезапуска hf-agent.' >&2
    exit 1
fi

echo "Готово: Low контейнеров пересоздано ${#low_compose[@]}, Middle контейнеров пересоздано ${#middle_compose[@]}."
echo "hf-agent обновлён; прежний бинарник сохранён как $agent_backup."
