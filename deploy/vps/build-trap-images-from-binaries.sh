#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
stamp=$(date +%Y%m%d-%H%M%S)
artifact_dir=${1:-/root/mellcore-trap-images-$stamp}
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
[[ ! -e $artifact_dir ]] || { echo "Каталог уже существует: $artifact_dir" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Не найден Docker.' >&2; exit 1; }
docker info >/dev/null

if [[ -n ${MELLCORE_BINARY_DIR:-} ]]; then
    binary_dir=$(realpath "$MELLCORE_BINARY_DIR")
    low_binary=$binary_dir/honeyforge-low
    middle_binary=$binary_dir/pritvoryashka
else
    low_binary=$repo/honeypots/kozyavka/target/release/honeyforge-low
    middle_binary=$repo/target/release/pritvoryashka
fi
for binary in "$low_binary" "$middle_binary"; do
    [[ -s $binary && -x $binary ]] || {
        echo "Не найден собранный Cargo-бинарник: $binary" >&2
        echo 'Сначала соберите Low и Middle через Cargo.' >&2
        exit 1
    }
done

mkdir -m 0700 -p "$artifact_dir"
artifact_dir=$(realpath "$artifact_dir")
work_dir=$(mktemp -d /tmp/mellcore-trap-image-build.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT
low_context=$work_dir/low
middle_context=$work_dir/middle
mkdir -p "$low_context/config" "$middle_context"

install -m 0755 "$low_binary" "$low_context/honeyforge-low"
install -m 0644 "$repo/honeypots/kozyavka/config/docker.json" "$low_context/config/docker.json"
cat > "$low_context/Dockerfile" <<'DOCKERFILE'
FROM debian:bookworm-slim
COPY honeyforge-low /usr/local/bin/honeyforge-low
COPY config/docker.json /etc/honeyforge/config.json
RUN /usr/local/bin/honeyforge-low --help >/dev/null
USER 65532:65532
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/honeyforge-low"]
CMD ["--config", "/etc/honeyforge/config.json"]
DOCKERFILE

install -m 0755 "$middle_binary" "$middle_context/pritvoryashka"
install -m 0755 "$repo/honeypots/pritvoryashka/docker-entrypoint.sh" "$middle_context/docker-entrypoint.sh"
install -m 0644 "$repo/honeypots/pritvoryashka/config-schema-probe.json" "$middle_context/config-schema-probe.json"
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
    && /usr/local/bin/pritvoryashka --check-config /tmp/hf-middle-config-schema-probe.json \
    && /usr/local/bin/pritvoryashka --check-windows-parser \
    && rm -f /tmp/hf-middle-config-schema-probe.json
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["/etc/honeyforge/pritvoryashka.json"]
DOCKERFILE

if [[ -n ${MELLCORE_OS_MATRIX_TEST_BINARY:-} ]]; then
    [[ -s $MELLCORE_OS_MATRIX_TEST_BINARY && -x $MELLCORE_OS_MATRIX_TEST_BINARY ]] || {
        echo "Не найден исполняемый тест Middle: $MELLCORE_OS_MATRIX_TEST_BINARY" >&2
        exit 1
    }
    install -m 0755 "$MELLCORE_OS_MATRIX_TEST_BINARY" "$middle_context/os-matrix-test"
    echo "Middle image: OS matrix будет выполнена внутри образа с PowerShell parser."
    cat >> "$middle_context/Dockerfile" <<'DOCKERFILE'
COPY os-matrix-test /tmp/os-matrix-test
RUN MELLCORE_REQUIRE_PWSH=1 /tmp/os-matrix-test --nocapture \
    && rm -f /tmp/os-matrix-test
DOCKERFILE
fi

low_tag=honeyforge-low:binary-update-$stamp
middle_tag=honeyforge-pritvoryashka:binary-update-$stamp
docker build --progress=plain --file "$low_context/Dockerfile" --tag "$low_tag" "$low_context"
docker build --progress=plain --file "$middle_context/Dockerfile" --tag "$middle_tag" "$middle_context"

low_user=$(docker image inspect --format '{{.Config.User}}' "$low_tag")
[[ $low_user == '65532:65532' ]] || { echo "Неверный пользователь Low image: $low_user" >&2; exit 1; }
bash "$repo/deploy/vps/check-middle-image.sh" "$middle_tag"

for kind in low middle; do
    case "$kind" in
        low) local_tag=honeyforge-low:local; built_tag=$low_tag; archive=low.tar ;;
        middle) local_tag=honeyforge-pritvoryashka:local; built_tag=$middle_tag; archive=middle.tar ;;
    esac
    old_id=$(docker image inspect --format '{{.Id}}' "$local_tag" 2>/dev/null || true)
    if [[ -n $old_id ]]; then
        rollback_tag="${local_tag%:*}:rollback-$stamp"
        docker tag "$old_id" "$rollback_tag"
        echo "Старый $local_tag сохранён как $rollback_tag"
    fi
    docker tag "$built_tag" "$local_tag"
    docker save --output "$artifact_dir/.$archive.tmp" "$local_tag"
    mv "$artifact_dir/.$archive.tmp" "$artifact_dir/$archive"
done

(
    cd "$artifact_dir"
    sha256sum low.tar middle.tar > SHA256SUMS
)
cat > "$artifact_dir/README.txt" <<EOF
Готовые Docker-образы ловушек, собранные из Cargo-бинарников:
  honeyforge-low:local
  honeyforge-pritvoryashka:local

Архивы для docker load: low.tar и middle.tar.
Бинарники Cargo, backend, frontend и образы системных сервисов скрипт не собирает и не меняет.
EOF
echo "Собраны только Docker-образы Low и Middle из существующих Cargo-бинарников."
echo "Архивы и SHA256: $artifact_dir"
