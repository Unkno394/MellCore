# MellCore на текущем VPS

Запуск из SSH root:

```sh
bash /root/MellCore/deploy/vps/install.sh /root/mellcore-upload-20261011-210018
```

Скрипт рассчитан на Ubuntu 24.04, существующий Docker и nginx, работающую Hysteria 2
и её сертификат для `yourpasswordforemail.ru` в `/var/lib/hysteria/acme`.
Если загруженные host-бинарники устарели, обновите только их из текущих исходников:

```sh
bash /root/MellCore/deploy/vps/rebuild-host-binaries.sh /root/mellcore-upload-20261011-210018
```

Скрипт использует Docker с Rust 1.95 и не трогает сервисы VPS. Старые бинарники
сохраняются в `/root/mellcore-artifact-backups/`. Образы `low.tar` и `middle.tar`
остаются из загруженного комплекта.

Чтобы добавить ClickHouse к уже работающему VPS отдельно от полного установщика,
запустите `bash /root/MellCore/deploy/vps/install-clickhouse.sh`. Скрипт создаёт пароль
в существующем хранилище секретов, поднимает только ClickHouse и проверяет таблицу;
PostgreSQL и остальные сервисы не перезапускаются. Для записи новых событий после этого
нужен `hf-center`, собранный с ClickHouse sink и параметрами `HF_CENTER_CLICKHOUSE_*`.

Установщик принимает каталог артефактов первым аргументом или из
`MELLCORE_ARTIFACT_DIR`; если найден ровно один `/root/mellcore-upload-*`, он
выбирается автоматически. Перед изменениями проверяются ELF-бинарники, архитектура
и теги Docker-образов, а также пути внутри High-архива. Затем образы загружаются
через `docker load`, бинарники устанавливаются из каталога, оригиналы сохраняются
в `/root/mellcore-backups/binaries`, а контрольные суммы записываются в
`/opt/mellcore/artifacts/SHA256SUMS`. Cargo и пересборки не используются.
После установки скрипт проверяет миграции, вход Admin, ресурсы, HTTPS,
доставку команд и события в БД.

Для этой версии `hf-center` и `hf-agent` должны быть собраны после последних
изменений в репозитории: проверка требует `HF_CENTER_CREDENTIALS_FILE` и настройки
telemetry. Несовместимый набор остановит установку до изменения файлов и сервисов.

## Компоненты

* PostgreSQL: отдельный Compose project `mellcore-vps`, persistent volume, loopback 54329.
* ClickHouse: тот же Compose project, отдельный persistent volume, только loopback HTTP 8123.
  Center сначала надёжно сохраняет принятые HFSP-события в JSONL spool, затем доставляет их
  в `honeyforge.telemetry_events`; при недоступности ClickHouse spool сохраняется и отправка
  повторяется. `ReplacingMergeTree` устраняет дубли при повторной доставке одного event ID.
* Backend: `honeyforge-backend.service`, loopback 18080, публичный JWT API `/api/v1/`.
* Center: `hf-center.service`, loopback 18081 и UDP 44000, индивидуальная авторизация Hysteria.
* Agent: `hf-agent.service`, постоянная identity и SQLite outbox в
  `/var/lib/honeyforge/mellcore-local-agent`; команды доставляются через Hysteria.
  Агент собирает события Low из Docker stdout и Middle из `runtime/events.jsonl`,
  отправляет их через Kazik внутри Hysteria с durable ACK. Центр пишет принятые события
  в `/var/lib/honeyforge/telemetry/events.jsonl`, а затем в ClickHouse.
* Hysteria: существующий QUIC/UDP 443 и ACME cache сохраняются. Статический пароль,
  выданный предыдущим скриптом, добавляется в credential store для совместимости.
* nginx: HTTPS/TCP 443 на том же домене, операторская панель защищена HTTP Basic. Control token
  хранится на VPS и автоматически передаётся nginx центру для команд панели; оператор его не вводит.
  Действующий ACME HTTP proxy остаётся на TCP 80. Сертификат копируется из ACME cache
  после проверки домена и соответствия ключа; systemd timer обновляет копию каждый час.
* Low и Middle: отдельные Docker-контейнеры на loopback 31001/31002.
* Dispatcher: `hf-dispatcher.service`, общий публичный SSH/TCP 2222, веса 50/50.
* ClickHouse доступен только локально на `127.0.0.1:8123`. Пароль хранится в
  `/etc/honeyforge/mellcore-secrets.json`; порт не публикуется наружу.
* Middle telemetry: HTTPS ingestion backend, события доступны через JWT API.
* Attack knowledge graph: PostgreSQL stores versioned techniques, semantic action nodes/edges,
  per-session incremental matching state and reviewable unknown-action proposals. Center mirrors
  its durable telemetry spool to the backend's loopback-only `/internal/v1/center/events` endpoint;
  ClickHouse remains the event analytics store. Similarity is reported as candidate/attempt and
  only an independently confirmed host escape is marked confirmed. Owned results are available at
  `GET /api/v1/traps/{trap_id}/attack-matches`; administrators can inspect aggregated unknown
  action proposals at `GET /api/v1/knowledge/proposals` before manually curating the knowledge base.

Данные входа и Control token: `/root/mellcore-access.txt`, права 0600.
Секреты не коммитятся. Повторный запуск использует прежнюю БД, passwords и resource IDs.
Существующие конфиги Hysteria и резервные копии БД находятся в `/root/mellcore-backups`.
Скрипт не удаляет PostgreSQL volume. При первой установке занятые служебные порты
и существующий `hf-agent.service` требуют отдельной проверки.

Проверка `verify-and-seed.py` ставит три команды через Center и ожидает сохранённых
агентом результатов. Это проверяет реальную доставку Kazik через SOCKS5 UDP и QUIC,
а не только факт старта systemd. После этого проверяются SSH banners обоих контейнеров
и Dispatcher, действующий HTTPS certificate и события Middle в PostgreSQL.

## Текущие границы проекта

Это запуск реализованных компонентов, а не завершённая интеграция всех подсистем.
Backend работает с `INTEGRATION_MODE=mock`: изменения desired_state через CRUD
сами не запускают агент. Начальные ресурсы разворачивает проверочный скрипт,
а дальнейшие команды отправляются через операторскую панель Center.
Backend actual_state не подменяется фиктивным running.

Center сохраняет agent credentials, но enrollment tokens и pending commands всё ещё
находятся в памяти. Outbox агента и выполненные команды сохраняются в SQLite/JSON.
Отзыв агента доступен в панели: Center сначала удаляет индивидуальный credential
из постоянного хранилища, очищает его очередь команд, затем закрывает активную
Hysteria-сессию через loopback Traffic Stats API и проверяет `/online`. Если API
недоступен, панель явно показывает частичный результат; повторный отзыв пытается
закрыть сессию снова. Отзыв доступа не удаляет программу и ловушки на удалённом VPS:
ловушки нужно удалить до отзыва. Удаление Low/Middle останавливает контейнер,
кладёт последние события в SQLite outbox и затем удаляет Compose-проект. High VM
удаляется через её штатный reset-скрипт. При удалении ловушки из общей группы
агент сначала удаляет её маршрут, пропорционально перераспределяет веса и
перезапускает Dispatcher с проверкой запуска. Если в группе не осталось ловушек,
её публичный listener удаляется; если маршрутов больше нет, Dispatcher останавливается
и отключается. При ошибке остановки ловушки агент сначала восстанавливает её
контейнер, затем прежний маршрут; если контейнер не поднялся, маршрут остаётся
отключённым. Перезапуск Dispatcher прерывает текущие соединения через него.

Для включения отзыва на уже работающем Center после сборки и установки новых
`hf-center` и `hf-agent` запустите
`bash /root/MellCore/deploy/vps/enable-agent-revocation.sh`. Скрипт сохраняет
резервные копии, добавляет секрет и loopback API Hysteria на 127.0.0.1:19999,
перезапускает Hysteria и Center и проверяет `/online`. В панели после обновления
Center доступны отдельные действия «Удалить ловушку» и «Отозвать доступ»;
панель ждёт Kazik ACK агента и показывает выполнение либо ошибку команды.
Статусы команд пока находятся в памяти Center и после перезапуска не сохраняются.

Наблюдение за процессами находится в `hf-agent`: на Linux агент
запускает `bpftrace` для eBPF tracepoint `sched_process_exec`, видит запуски на
хосте и в контейнерах, сопоставляет PID с Docker Compose project ловушки по
метке контейнера и сверяет cgroup и PID/mount namespaces через `/proc`. В Center
отправляются только события, связанные с известной ловушкой:
`security.process_exec`,
`security.unexpected_executable`, `security.namespace_mismatch` и
`security.host_exec_from_trap`, а также `security.policy_violation` для
нарушения runtime/resource-политики идут через тот же
SQLite outbox и Kazik в ClickHouse. Поток ограничен 100 обычными и 20
подозрительными событиями в минуту на агента; при превышении агент пишет
предупреждение в journal. При отсутствии `bpftrace` или прав на eBPF агент
продолжает управлять ловушками и повторяет запуск наблюдателя. На новых
Ubuntu/Debian bootstrap устанавливает `bpftrace` и `nftables`.
Если локальный SOCKS5 Hysteria недоступен, наблюдатель продолжает работу,
события остаются в SQLite, а транспорт переподключается каждые 5 секунд.

Неожиданный бинарник внутри контейнера и совпадение одного namespace с хостом
дают только подозрение. Для `security.escape_confirmed` агент через 250 мс
повторно проверяет тот же PID/starttime, оба host namespaces, cgroup
конкретного контейнера, Docker label и безопасные runtime-настройки.
Подтверждённый инцидент сохраняется в root-owned каталоге `security`, его
сообщение кладётся в SQLite outbox, новые команды блокируются. Агент ждёт ACK
Center до 15 секунд, после чего запускает `honeyforge-emergency.service`.
Служба останавливает Compose-проект ловушки, блокирует входящий/исходящий
трафик и forwarding через `nft`, затем вызывает `systemctl poweroff`.

Служба устанавливается агентом, но запуск реакции требует
`HF_EMERGENCY_ARMED=1` в окружении `hf-agent.service`. До проверки на отдельной
тестовой VDS **не включайте** этот флаг на рабочем сервере. При отсутствии флага
инцидент и тревога всё равно сохраняются, новые команды остаются заблокированы.
Включение флага позднее не выключит VDS задним числом по старому инциденту.
Короткоживущий процесс может завершиться до чтения `/proc`, а снимок Docker
обновляется раз в 10 секунд, поэтому детектор не гарантирует обнаружение всех
вариантов побега.

При `security.escape_confirmed` Center сначала сохраняет событие в durable
telemetry spool, затем сохраняет пометку о скомпрометированном агенте и target
hostname/IP в `/var/lib/honeyforge/center-agent-security.json`, отзывает его
credential, очищает pending-команды и отклоняет дальнейшие Hysteria/Kazik
подключения и команды. Center отправляет ACK сохранённого инцидента и закрывает
активную Hysteria-сессию через Traffic Stats API; если API временно недоступен,
повторяет попытку каждые 15 секунд и после перезапуска. Повторный bootstrap на
тот же нормализованный hostname/IP отклоняется. Панель показывает список
скомпрометированных узлов и состояние закрытия транспорта. У старых агентов,
которые не проходили bootstrap после появления этого реестра, target-адрес может
быть неизвестен — тогда инцидент всё равно связывается с agent ID.

### Политики Low и Middle

Новые контейнеры, созданные обновлённым `hf-agent`, получают лимиты Docker:
Low — память 128 MiB, CPU 0.50, до 64 PID и `nofile` 256; Middle — 512 MiB,
CPU 1.0, до 256 PID и `nofile` 1024. Middle принимает не более 128 одновременных
SSH-сессий. У обоих root filesystem read-only,
все capabilities сняты, `no-new-privileges` включён; host PID/network/IPC
namespaces запрещены. Low запускается от пользователя образа 65532 и имеет
только read-only конфиг-монтирование. Middle работает с SSH host key в одном
отдельном writable runtime-монтировании; остальные файлы контейнера read-only.
При проверке кандидата побега агент сверяет эти ограничения с `docker inspect`,
а также отклоняет дополнительные mounts и опубликованные порты. Этот runtime
снимок проверяется именно при проверке кандидата, а не непрерывно.

Low разрешён только один сетевой listener TCP для SSH banner; SSH-аутентификации,
shell и запуска команд в Low нет. Middle принимает SSH и исполняет фиксированный
набор команд из `honeypots/pritvoryashka/src/shell/commands.rs`; это команды
виртуального shell, они не запускаются на host и работают с изолированной
виртуальной файловой системой. Пути нормализуются внутри неё; shell operators,
пайпы, перенаправления и command substitution отклоняются. У виртуальной FS
есть пределы 4096 объектов, 1 MiB на файл и 4 MiB суммарно. Сессии Middle
ограничены 128 одновременными подключениями, 8192 байтами ввода на команду и
600 секундами бездействия. Эти настройки задаются конфигом ловушки.

Сетевой egress контейнеров пока не ограничен allowlist-ом: Docker-изоляция
пространств и публикация заданного SSH-порта настроены, но исходящие соединения
из контейнера ещё не запрещены. Политика разрешённых доменов/IP и непрерывный
контроль изменения Docker-конфигурации остаются следующими задачами. Неожиданные
исполняемые файлы сейчас дают событие/предупреждение, но не принудительно
завершаются.

Отправка SMTP-писем требует SMTP settings; без них восстановление пароля и
подтверждение email недоступны. Полноценный frontend регистрации/управления
пользователями и WebSocket отсутствуют в репозитории.
High Ubuntu recipe подготовлен для удалённого KVM-capable VPS. Этот хост без
`/dev/kvm` не может запустить High VM; установка не создаёт её автоматически.

## Диагностика

```sh
systemctl status honeyforge-backend hf-center hf-agent hf-hysteria-client hysteria-server hf-dispatcher
journalctl -u hf-agent -u hf-center -u honeyforge-backend -n 100 --no-pager
tail -n 20 /var/lib/honeyforge/telemetry/events.jsonl
docker exec mellcore-vps-clickhouse-1 clickhouse-client --query \
  'SELECT received_at_unix_ms, agent_id, event_type, source_ip, destination_port FROM honeyforge.telemetry_events FINAL ORDER BY received_at_unix_ms DESC LIMIT 20'
python3 /root/MellCore/deploy/vps/verify-and-seed.py
cat /root/mellcore-access.txt
```

Firewall хостинга должен пропускать TCP 80, TCP/UDP 443 и TCP 2222.
SSH сервера и панель ISPmanager продолжают использовать свои прежние порты.
