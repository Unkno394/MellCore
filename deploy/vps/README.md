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
* Backend: `honeyforge-backend.service`, loopback 18080, публичный JWT API `/api/v1/`.
* Center: `hf-center.service`, loopback 18081 и UDP 44000, индивидуальная авторизация Hysteria.
* Agent: `hf-agent.service`, постоянная identity и SQLite outbox в
  `/var/lib/honeyforge/mellcore-local-agent`; команды доставляются через Hysteria.
  Агент также забирает события Low из Docker stdout и Middle из `runtime/events.jsonl`,
  отправляет их через Kazik с durable ACK. Центр дописывает принятые события в
  `/var/lib/honeyforge/telemetry/events.jsonl` (файл содержит записанные ловушкой имена пользователей).
* Hysteria: существующий QUIC/UDP 443 и ACME cache сохраняются. Статический пароль,
  выданный предыдущим скриптом, добавляется в credential store для совместимости.
* nginx: HTTPS/TCP 443 на том же домене, операторская панель защищена HTTP Basic. Control token
  хранится на VPS и автоматически передаётся nginx центру для команд панели; оператор его не вводит.
  Действующий ACME HTTP proxy остаётся на TCP 80. Сертификат копируется из ACME cache
  после проверки домена и соответствия ключа; systemd timer обновляет копию каждый час.
* Low и Middle: отдельные Docker-контейнеры на loopback 31001/31002.
* Dispatcher: `hf-dispatcher.service`, общий публичный SSH/TCP 2222, веса 50/50.
* Middle telemetry: HTTPS ingestion backend, события доступны через JWT API.

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
Отзыв активных Hysteria sessions не реализован.

Отправка SMTP-писем требует SMTP settings; без них восстановление пароля и
подтверждение email недоступны. Полноценный frontend регистрации/управления
пользователями, ClickHouse и WebSocket отсутствуют в репозитории.
High Ubuntu recipe подготовлен для удалённого KVM-capable VPS. Этот хост без
`/dev/kvm` не может запустить High VM; установка не создаёт её автоматически.

## Диагностика

```sh
systemctl status honeyforge-backend hf-center hf-agent hf-hysteria-client hysteria-server hf-dispatcher
journalctl -u hf-agent -u hf-center -u honeyforge-backend -n 100 --no-pager
tail -n 20 /var/lib/honeyforge/telemetry/events.jsonl
python3 /root/MellCore/deploy/vps/verify-and-seed.py
cat /root/mellcore-access.txt
```

Firewall хостинга должен пропускать TCP 80, TCP/UDP 443 и TCP 2222.
SSH сервера и панель ISPmanager продолжают использовать свои прежние порты.
