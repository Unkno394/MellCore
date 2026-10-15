#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

bundle_dir=${1:-/tmp/mellcore-agent-ssh-auth-update}
[[ $EUID -eq 0 ]] || { echo 'Запусти скрипт от root на сервере агента.' >&2; exit 1; }
[[ -d $bundle_dir ]] || { echo "Не найден каталог обновления: $bundle_dir" >&2; exit 1; }
bundle_dir=$(realpath "$bundle_dir")

for name in hf-agent hf-dispatcher; do
    binary="$bundle_dir/$name"
    [[ -s $binary && -x $binary ]] || { echo "Не найден исполняемый бинарник: $binary" >&2; exit 1; }
    file "$binary" | grep -q 'ELF 64-bit.*x86-64' || { echo "Ожидался ELF x86-64: $binary" >&2; exit 1; }
    if ldd "$binary" | grep -q 'not found'; then
        echo "Для $name не найдены системные библиотеки." >&2
        exit 1
    fi
    "$binary" --help >/dev/null
    [[ -x "/usr/local/bin/$name" ]] || { echo "Не найден установленный /usr/local/bin/$name" >&2; exit 1; }
done

stamp=$(date +%Y%m%d-%H%M%S)
backup="/var/backups/mellcore-agent-$stamp"
install -d -m 0700 "$backup"
cp -a /usr/local/bin/hf-agent /usr/local/bin/hf-dispatcher "$backup/"
dispatcher_was_active=0
if systemctl is-active --quiet hf-dispatcher.service; then dispatcher_was_active=1; fi

restore_binaries() {
    install -m 0755 "$backup/hf-agent" /usr/local/bin/.hf-agent.rollback
    mv -f /usr/local/bin/.hf-agent.rollback /usr/local/bin/hf-agent
    install -m 0755 "$backup/hf-dispatcher" /usr/local/bin/.hf-dispatcher.rollback
    mv -f /usr/local/bin/.hf-dispatcher.rollback /usr/local/bin/hf-dispatcher
    systemctl restart hf-agent.service || true
    if (( dispatcher_was_active )); then systemctl restart hf-dispatcher.service || true; fi
}

install -m 0755 "$bundle_dir/hf-agent" /usr/local/bin/.hf-agent.new
install -m 0755 "$bundle_dir/hf-dispatcher" /usr/local/bin/.hf-dispatcher.new
mv -f /usr/local/bin/.hf-agent.new /usr/local/bin/hf-agent
mv -f /usr/local/bin/.hf-dispatcher.new /usr/local/bin/hf-dispatcher

if ! systemctl restart hf-agent.service || ! systemctl is-active --quiet hf-agent.service; then
    echo 'Новый hf-agent не запустился; восстанавливаю прежние бинарники.' >&2
    restore_binaries
    systemctl status hf-agent.service --no-pager -l || true
    exit 1
fi
if (( dispatcher_was_active )) && ! systemctl restart hf-dispatcher.service; then
    echo 'Новый hf-dispatcher не запустился; восстанавливаю прежние бинарники.' >&2
    restore_binaries
    systemctl status hf-dispatcher.service --no-pager -l || true
    exit 1
fi

echo "hf-agent и hf-dispatcher обновлены. Резервные копии: $backup"
systemctl status hf-agent.service --no-pager -l || true
if (( dispatcher_was_active )); then systemctl status hf-dispatcher.service --no-pager -l || true; fi
