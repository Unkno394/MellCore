# hf-cli

`hf-cli` устанавливает команду `hf` для управления ловушками на локальном Linux-сервере. Это отдельный пакет: он не устанавливает и не запускает `hf-agent`, не регистрируется в Центре, не использует Kazik или другой протокол управления и не отправляет телеметрию атак.

Установка из исходного репозитория:

```sh
cargo install --path crates/hf-cli --locked
```

После публикации пакета команда установки из crates.io: `cargo install hf-cli`. Оба бинарника (`hf` и `hf-local-dispatcher`) устанавливаются вместе.

## Команды

```sh
sudo hf deploy low --port 2222
sudo hf deploy medium --port 2223
sudo hf deploy high --os ubuntu --port 2224
sudo hf deploy high --os debian --port 2225
sudo hf deploy high --os arch --port 2226
sudo hf deploy high --os windows --port 3389

# Второй способ: предварительно скачанный ISO на этом же сервере.
sudo hf deploy high --os ubuntu --iso /srv/iso/ubuntu-server.iso --port 2227

sudo hf list
sudo hf stop high-1
sudo hf remove high-1
```

Low и Medium используют предварительно загруженные Docker-образы `honeyforge-low:local` и `honeyforge-pritvoryashka:local`. Их можно заменить через `HF_KOZYAVKA_IMAGE` и `HF_PRITVORYASHKA_IMAGE`.

У High два способа запуска. `--os ubuntu|debian|arch|windows` выбирает готовый образ из `/var/lib/honeyforge/images`; если Linux-образа ещё нет, CLI загружает его через проверенный рецепт. Для Windows нужен подготовленный `windows-server-prepared.qcow2` и его `.sha256` рядом; при наличии локального `hf-image-builder` и утверждённого каталога источников CLI может собрать его на сервере. `--image /путь/к/готовому.qcow2` переопределяет путь к готовому образу. Не перемещайте базовый QCOW2, пока от него работают VM.

`--iso /путь/к/файлу.iso` устанавливает выбранную через `--os` ОС из **локального ISO**, который пользователь скачал и положил на тот же сервер. CLI проверяет тип ISO, разворачивает новую VM, дожидается установки и готовности SSH или RDP и только затем открывает указанный порт. Поддерживаются серверные ISO Ubuntu, Debian и Arch, а также Windows Server 2022 Evaluation. Установщику могут потребоваться дополнительные пакеты на хосте: `xorriso`, `cloud-localds`, `virt-customize`, `expect`, `wimlib-imagex` и инструменты из соответствующего High-рецепта. Для ISO нужны свободное место под исходный образ, временный установочный образ и отдельный диск VM.

Перед High CLI проверяет `/dev/kvm`, libvirt/QEMU и команды, нужные выбранной ОС и способу установки. Если на Debian/Ubuntu чего-то не хватает, CLI сам устанавливает недостающие пакеты через `apt-get`, запускает `libvirtd` и повторно проверяет готовность до создания VM. Для этого запускайте `sudo hf deploy high ...`; серверу нужен доступ к репозиториям пакетов. При создании подготовленных Ubuntu и Debian образов CLI заранее устанавливает и включает `qemu-guest-agent` в отдельной базовой копии до запуска VM. Установка пакета выполняется `virt-customize` внутри отдельного libguestfs appliance с ограниченным исходящим сетевым доступом. CLI устанавливает `dhcpcd-base` на хосте, чтобы libguestfs мог включить DHCP-клиент в appliance; сетевые запросы при этом идут из appliance, а не из будущей VM. Для Arch CLI включает уже установленный агент и `systemd-networkd` в копии диска и использует DHCP-конфигурацию для интерфейса с любым именем, включая `eth0`. Если зеркало, DNS или DHCP в appliance недоступны, CLI завершает подготовку с ошибкой до запуска VM. Пользовательский `--image` должен уже содержать пакет `qemu-guest-agent`, иначе CLI завершится с диагностикой до запуска. На других host-дистрибутивах зависимости пока нужно установить вручную. Сеть High задаётся в libvirt с `forward mode=none`; фильтры IPv4 и IPv6 запрещают гостю доступ к хосту и маршрутизацию наружу, а публикация добавляет только проверенные правила для SSH или RDP. CLI проверяет, что SSH banner отвечает из гостевой сети и что точные правила проброса установлены. Доступность внешнего порта через firewall провайдера или внешнюю NAT-сеть нужно проверить с другой машины.

CLI хранит только локальную запись о ловушке (`id`, `kind`, `port`, `status`) в `/var/lib/honeyforge/local/traps.json`. Другой абсолютный каталог можно задать через `HF_LOCAL_STATE_DIR`.

## Параметры ловушек

Пароли передаются через файл с правами `0600`, чтобы не оставлять их в истории команд и списке процессов. CLI принимает путь к файлу, а не пароль в аргументе.

```sh
printf '%s\n' 'example-password' | sudo tee /root/hf-password >/dev/null
sudo chmod 600 /root/hf-password

# Low: capture_credentials, configured, any_password, passwordless
sudo hf deploy low --port 2225 --shared --auth-mode configured --username admin --password-file /root/hf-password --cpu 0.25 --memory-mb 96 --pids 48

# Middle: ubuntu, debian, arch, windows; adaptive или realistic SSH
sudo hf deploy medium --port 2225 --shared --weight 40 --os debian --hostname srv-app-01 --username admin --ssh-auth-mode realistic --password-file /root/hf-password --vulnerability redis_unauthenticated_access --bait /home/admin/.env=/root/decoy.env

# High: отдельная Linux VM с настройкой гостя через QEMU Guest Agent
sudo hf deploy high --os ubuntu --port 2224 --hostname web-01 --username admin --shell bash --password-file /root/hf-password --bait /home/admin/.env=/root/decoy.env

# Использование уже подготовленного QCOW2 по своему пути:
sudo hf deploy high --os debian --image /srv/images/debian.qcow2 --port 2228

# Установка из собственного ISO; файл уже должен находиться на сервере:
sudo hf deploy high --os debian --iso /srv/iso/debian-12-amd64-DVD-1.iso --port 2229
```

При `--shared` CLI запускает `hf-local-dispatcher` как отдельный systemd-сервис. Участники общего порта используют один SSH-ключ; Middle получает клиентский IP через аутентифицированный PROXYv2. Без `--shared` ловушка слушает свой порт напрямую. `--weight` задаёт долю новой ловушки при добавлении к существующему общему порту.

Middle поддерживает профили `ssh_weak_credentials`, `ssh_root_login_enabled`, `redis_unauthenticated_access`, `docker_api_exposed`, `http_admin_panel_exposure`, `web_path_traversal`, `web_command_injection`, `sql_database_weak_credentials`, `ftp_anonymous_login`; для Windows: `win_autologon_credentials`, `win_always_install_elevated`, `win_writable_service_binary`, `win_guest_share`. Сервисные порты можно задать через `--service-port redis=16379` или `--service-port docker=2375` (также принимается `docker_api`); без этого CLI выбирает свободный порт начиная с 30000. Приманки можно размещать в домашнем каталоге указанного `--username`, например `/home/testuser/notes.txt`.

Linux High поддерживает `ssh_weak_credentials`, `ssh_root_login_enabled`, `sudo_nopasswd`; это осознанно уязвимые настройки только гостевой VM. Для shell `zsh` он должен быть установлен в госте. CLI создаёт отдельный QCOW2 overlay для готового образа либо новый диск при установке из ISO. Локальное состояние ловушек не отправляется в Центр. `--bait` записывает текстовый файл в госте; Middle ограничивает содержимое 4 КиБ на файл и виртуальные пути, High — 4 КиБ на файл и `/srv`, `/opt`, `/var/backups` либо домашний каталог выбранного пользователя. Пароль, созданный установщиком High, CLI сохраняет в файле под `/var/lib/honeyforge/local/high/` и выводит путь к нему.
