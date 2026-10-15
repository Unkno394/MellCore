#!/usr/bin/env bash
# Make the images built on Center available to future agent SSH bootstraps.
set -Eeuo pipefail
umask 077

[[ $EUID -eq 0 ]] || { echo 'Запустите от root на центральном сервере.' >&2; exit 1; }
images=${1:-/root/mellcore-trap-images-20261014-013500}
installed=/opt/mellcore/artifacts
center_env=/etc/honeyforge/center.env
for name in low.tar middle.tar SHA256SUMS; do
    [[ -s $images/$name ]] || { echo "Не найден $images/$name" >&2; exit 1; }
done
(cd "$images" && sha256sum --check SHA256SUMS)
[[ -d $installed && -f $center_env ]] || {
    echo 'На этом сервере не найдены артефакты или конфигурация Центра.' >&2
    exit 1
}
grep -Fxq "HF_KOZYAVKA_IMAGE_ARCHIVE=$installed/low.tar" "$center_env"
grep -Fxq "HF_PRITVORYASHKA_IMAGE_ARCHIVE=$installed/middle.tar" "$center_env"

backup=/root/mellcore-artifact-backups/trap-images-$(date +%Y%m%d-%H%M%S)
install -d -m 0700 "$backup"
cp -a "$installed/low.tar" "$installed/middle.tar" "$installed/SHA256SUMS" "$backup/"
for name in low.tar middle.tar; do
    install -m 0600 "$images/$name" "$installed/.$name.new"
    mv -f "$installed/.$name.new" "$installed/$name"
done
sha256sum "$installed"/bin/* "$installed"/*.tar* > "$installed/.SHA256SUMS.new"
chmod 0600 "$installed/.SHA256SUMS.new"
mv -f "$installed/.SHA256SUMS.new" "$installed/SHA256SUMS"
echo "Образы для новых агентов обновлены. Резервная копия: $backup"
sha256sum "$installed/low.tar" "$installed/middle.tar"
