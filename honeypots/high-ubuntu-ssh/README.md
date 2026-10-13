# HoneyForge High: Ubuntu SSH VM

Первая High-ловушка — настоящая Ubuntu Server VM с OpenSSH, не Docker-контейнер.
Каждому экземпляру создаётся QCOW2 overlay поверх неизменяемого trusted base image;
при пересоздании удаляется только overlay.

SandboxManager запускает VM только на отдельном KVM-capable VPS. Guest не получает Docker
socket, libvirt socket, HoneyForge credentials или management сеть. Внешний порт публикует
host Dispatcher/NAT, guest использует isolated network.

Профиль: Ubuntu 24.04 cloud image, 2 vCPU, 2048 MiB RAM, 20 GiB overlay и настоящий
OpenSSH. Reset удаляет NAT-правила экземпляра, останавливает VM, удаляет overlay и seed;
следующий запуск создаёт чистый экземпляр.

cloud-init настраивает уже присутствующий в trusted image OpenSSH, добавляет приманочные данные
и офлайн устанавливает гостевой telemetry sensor из seed ISO. Во время cloud-init пакеты из
Интернета не устанавливаются: в базовом образе должны присутствовать `python3`, `journalctl` и
`sshd`. При первом запуске Agent сам скачивает
официальный Ubuntu 24.04 amd64 cloud image в `/var/lib/honeyforge/images/`, сверяет SHA-256 с
официальным `SHA256SUMS`, затем скрипт create-overlay создаёт из него QCOW2 overlay и cloud-init
seed. Новый `DeployHighVm` принимает только agent-managed путь встроенного профиля; загрузка
произвольных пользовательских образов не поддерживается. Старый `DeployHighUbuntu` сохранён для
wire-совместимости с уже развёрнутыми Ubuntu trap.

Запуск первой VM выполняет scripts/launch.sh:

    sh scripts/launch.sh /srv/honeyforge/images/ubuntu-24.04.qcow2 INSTANCE_UUID 1488

Он создаёт isolated libvirt network, overlay и VM hf-high-INSTANCE_UUID. Скрипт reset.sh
останавливает VM, удаляет definition и рабочий overlay:

    sh scripts/reset.sh INSTANCE_UUID

Для установки recipe вместе с агентом центр получает архив:

    sh scripts/package-recipe.sh /tmp/hf-high-ubuntu-ssh.tar.gz

и запускается с `HF_HIGH_UBUNTU_RECIPE_ARCHIVE=/tmp/hf-high-ubuntu-ssh.tar.gz`.
Bootstrap распаковывает из него `high-ubuntu-ssh`, `high-arch-ssh` и `high-windows-rdp` в
`/usr/local/lib/honeyforge/`; основной lifecycle выбирает recipe по типизированному OS profile.

## High telemetry v1

libvirt создаёт приватный virtio-serial channel с именем
`org.honeyforge.telemetry.0`. В госте sensor открывает
`/dev/virtio-ports/org.honeyforge.telemetry.0`, а `hf-agent` подключается к Unix socket
`$HF_STATE_DIR/high/INSTANCE_UUID/telemetry.sock`. Guest отправляет ограниченные 16 KiB JSONL
события и никогда не получает `trap_id`, `agent_id`, Kazik credentials или management-команды.
Sensor не является полностью скрытым: root внутри скомпрометированной VM может увидеть,
остановить или подменить его, поэтому host считает все guest-поля недоверенными.

Sensor читает journal OpenSSH и `/var/log/audit/audit.log`. Он формирует `guest.boot`,
`guest.shutdown`, `sensor.heartbeat`, SSH authentication/session, `process.exec`, ограниченный
`process.exit`, file create/modify/delete/rename/permissions, outbound connect и sudo/su events.
Audit records группируются по serial до `EOE`; `ses` используется как SSH/audit session context.
До получения
host ACK событие остаётся в ограниченном guest outbox
`/var/lib/honeyforge-high-telemetry/outbox.jsonl`. Agent проверяет событие, назначает доверенные
идентификаторы и sequence, коммитит его в `$HF_STATE_DIR/high-telemetry.sqlite` с WAL и
`synchronous=FULL`, и только после этого отвечает ACK. Повтор с тем же guest event id возвращает
тот же host event id; повтор с изменённым содержимым отклоняется.

Host queue по умолчанию ограничена 100000 событиями
(`HF_HIGH_TELEMETRY_MAX_PENDING`). При заполнении ACK не отправляется, поэтому guest продолжает
повтор. Guest outbox ограничен 10000 событиями и 16 MiB; переполнение явно пишется в journal.
Незавершённые audit groups также ограничены 1024; вытеснение отражается diagnostic counter/event.
`process.exec` означает подтверждённый kernel audit syscall, а не обязательно строку, введённую в
shell. Built-ins (`cd`, `export`, aliases) без `execve` не видны. `process.exit` отражает вызов
`exit/exit_group`; аварийное завершение без такого syscall не гарантируется. Терминальный ввод и
содержимое файлов не записываются. tlog не включён до появления проверенной политики redaction.
Network audit v1 видит исход `connect(2)` и destination address, но не гарантирует source
IP/ephemeral port, transport protocol или host firewall reject: эти поля помечаются неизвестными.
Host-side libvirt даёт только aggregate RX/TX, а не flow records или PCAP.

Все поля события, пришедшие из VM, помечаются `provenance=untrusted_guest_report`; guest не может
заявить `event_origin=host`. Это защищает host identity/order/deduplication, но не делает sensor
доверенным после получения root внутри VM: такой атакующий всё ещё может скрыть или сфабриковать
guest-наблюдения.

Host events пока не отправляются в Kazik. Store уже создаёт bounded batch, стабильный
`message_id`, durable mapping на event IDs и готовый `KazikBody::Telemetry`. Удаление разрешено
только методом durable-ack. Текущий `Accepted` от центра не подтверждает запись в постоянное
хранилище, поэтому transport pump намеренно не активирован.

## Lifecycle и operational state

`$HF_STATE_DIR/traps/INSTANCE_UUID/high.json` хранит исходный deployment, desired state и
последнюю lifecycle-ошибку. Deploy/repeated command сверяет реальный domain, telemetry channel,
гостевой SSH/RDP service и DNAT. Stop снимает DNAT и останавливает domain без удаления overlay. Reset удаляет runtime
и пересоздаёт чистый overlay по manifest. Remove удаляет domain, DNAT, runtime и manifest.
После restart и затем с operational interval agent reconciles все High manifests. Это повторно
устанавливает policy после перезагрузки UFW/Docker/libvirt и завершает прерванный Remove без
воскрешения VM.

### Автономный локальный режим hf-agent

Для отдельного KVM test host High lifecycle и telemetry можно запустить без Center и
production-регистрации:

    sudo /usr/local/bin/hf-agent \
      --standalone-high \
      --state-dir /var/lib/honeyforge-standalone

Режим требует отдельный state dir, не читает и не создаёт production `identity.json`, не
подключает Hysteria/Kazik и принимает только High-команды. Команды помещаются JSON-файлами в
`/var/lib/honeyforge-standalone/inbox/`; успешно обработанные файлы перемещаются в `processed/`,
ошибочные — в `failed/`. `--command-file FILE --once` подходит для одной lifecycle-операции, но
после её завершения процесс уже не собирает telemetry. Для E2E оставляйте процесс запущенным либо
используйте отдельный локальный systemd unit с той же командой. Stop, Reset и Remove в этом режиме
разрешены только для High manifest из standalone state dir; агент не применяет legacy/Compose
fallback к неизвестной VM.

Раз в 30 секунд (настраивается `HF_HIGH_OPERATIONAL_INTERVAL_SECONDS`, минимум 5) agent заменяет
`$HF_STATE_DIR/high/INSTANCE_UUID/operational.json`. Это bounded current-state snapshot:
domain state, CPU time и рассчитанную по delta aggregate vCPU utilization, memory, disk bytes,
aggregate RX/TX, uptime, profile-aware SSH/RDP, DNAT и QGA readiness,
последняя lifecycle-ошибка и свежесть sensor heartbeat. Эти host-side данные продолжают
обновляться при остановленном guest sensor, но не заменяют flow-level network telemetry.

Isolated bridge разрешает гостям только DHCP к host, блокирует guest→host INPUT, IPv6 и любой
guest-initiated FORWARD к LAN/management сетям. Входящий DNAT разрешает только сервис конкретной VM,
не применяется к пакетам с High bridge и не может занять management SSH port 2222. Выделенные
цепочки вставляются перед UFW/Docker/libvirt policy и идемпотентно переустанавливаются при
публикации сервиса после restart; virtio channel bridge не использует.

Пароль `analyst` генерируется отдельно для каждого overlay. В seed хранится только SHA-512 hash,
а исходный пароль доступен root на KVM host в
`$HF_STATE_DIR/high/INSTANCE_UUID/ssh-password` с mode 0600. Не копируйте его в логи и после
контролируемого теста выполняйте Reset/Remove для удаления overlay и password file.

## Offline image

Для process/file/network telemetry нужен подготовленный image с auditd. В
`offline/README.md` описаны два воспроизводимых шага: создать versioned/checksummed deb bundle на
Ubuntu 24.04 amd64 и внедрить его вместе с QGA в производный QCOW2 через libguestfs. Runtime
cloud-init не вызывает apt и только устанавливает sensor/rules из seed ISO.

### Проверка на отдельном Linux/KVM host

Не выполняйте эти команды на production host без проверки путей и firewall. На тестовом Ubuntu
24.04 host с KVM/libvirt:

1. Установить собранный `hf-agent` и полный recipe в
   `/usr/local/lib/honeyforge/high-ubuntu-ssh`.
2. Убедиться, что trusted Ubuntu image содержит `python3`, systemd journal и OpenSSH server.
   Для расширенной telemetry использовать image, подготовленный по `offline/README.md`.
3. Запустить обычный `DeployHighUbuntu` через существующий AgentCommand flow.
4. Проверить `virsh dumpxml hf-high-INSTANCE_UUID`: должен быть channel target
   `org.honeyforge.telemetry.0`, а на host — `$HF_STATE_DIR/high/INSTANCE_UUID/telemetry.sock`.
5. Вызвать успешный и неуспешный SSH login через опубликованный DNAT port.
6. Проверить sensor через `virsh console` или offline image diagnostics:
   `systemctl status honeyforge-high-telemetry`.
7. Остановить `hf-agent`, повторить SSH attempt, затем запустить agent. Guest outbox должен
   опустеть только после reconnect; число строк в SQLite не должно удвоиться.
8. Для безопасной read-only проверки SQLite выполнить
   `sqlite3 -readonly /var/lib/honeyforge/high-telemetry.sqlite 'select event_id,trap_id,host_sequence from high_telemetry_events order by host_sequence;'`.

Локальные проверки без VM:

    cargo test -p hf-services high_telemetry
    cargo test -p hf-agent
    python3 -m unittest honeypots/high-ubuntu-ssh/tests/test_recipe.py
    python3 -m unittest honeypots/high-ubuntu-ssh/guest/test_high_telemetry_sensor.py honeypots/high-ubuntu-ssh/guest/test_high_telemetry_audit.py
