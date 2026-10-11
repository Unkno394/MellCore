# Pritvoryashka

Pritvoryashka — самостоятельная Middle Interaction SSH-ловушка на Rust. Она
принимает обычные SSH-клиенты, но никогда не запускает `/bin/sh`, команды ОС или
операции над файловой системой хоста. Каждая SSH-сессия получает собственную
копию виртуального Linux-окружения.

## Архитектура

- `ssh/` — `russh` server, парольная авторизация, PTY, shell/exec channels,
  terminal input, таймаут и лимит параллельных клиентов.
- `shell/` — безопасный tokenizer и детерминированные реализации команд.
- `filesystem/` — нормализованные виртуальные пути, файлы, каталоги, metadata,
  права и лимиты числа/размера объектов. Доступа к host FS нет.
- `deception/` — локальный конечный автомат сценария и метрика Deception Depth.
- `telemetry/` — события контракта HoneyForge v1, монотонный `sequence_no`,
  bounded queue, batching, retry, JSONL fallback и HTTP transport.
- `integration/` — `/health/live` и `/health/ready`.

Состояние `Shell`, VFS, история и deception engine принадлежат одному SSH
handler. После отключения handler и вся сессионная VFS освобождаются.

## Локальный запуск

Требуются Rust 1.95+ и OpenSSH `ssh-keygen` для первоначального host key.

```sh
ssh-keygen -t ed25519 -N '' -f honeypots/pritvoryashka/host_ed25519
cp honeypots/pritvoryashka/pritvoryashka.example.json pritvoryashka.json
cargo run --locked -p pritvoryashka -- pritvoryashka.json
```

Подключение:

```sh
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@127.0.0.1
```

В примере включена политика `accept_all`: принимается любой пароль, но в
телеметрию пишется только username. Для фиксированной пары задайте
`auth.policy=configured`, `auth.username` и `auth.password_env`; сам пароль
передайте только через указанную переменную окружения. `capture=password`
явно разрешает хранение введённых паролей в защищённом telemetry sink;
диагностические логи пароли не содержат.

Healthcheck:

```sh
curl --fail http://127.0.0.1:9091/health/live
curl --fail http://127.0.0.1:9091/health/ready
```

## Команды

Поддержаны `pwd`, `ls`, `cd`, `cat`, `echo`, `whoami`, `id`, `uname`,
`hostname`, `date`, `uptime`, `ps`, `top`, `history`, `mkdir`, `touch`, `rm`,
`cp`, `mv`, `head`, `tail`, `grep`, `find`, `clear`, `exit`.

Есть одинарные/двойные кавычки, пробелы в аргументах, backspace, Ctrl+C,
Ctrl+D, PTY и изменение размера терминала. Конвейеры, перенаправления,
подстановки, `&&`, `;` и job control намеренно отклоняются как unsupported
syntax. Неизвестная команда возвращает правдоподобный `command not found`.

## Adaptive Deception

Сценарий детерминирован и изолирован по сессиям:

1. Исследование `/var/log` открывает `/var/log/auth.log`.
2. Чтение `auth.log` открывает `/var/backups/app.env.bak`.
3. Чтение backup открывает `/home/admin/.ssh/config`.

Все значения в артефактах фиктивны. `session.ended` содержит
`deception_depth`, число уникальных объектов и переходов между стадиями.

## Телеметрия и HoneyForge

Событие содержит `event_id`, `trap_id`, `session_id`, `occurred_at`,
`sequence_no`, `event_type`, сетевые поля, `payload` и `metadata`. Поддержаны:

- `connection.opened`, `connection.closed`;
- `auth.attempted`, `auth.succeeded`, `auth.failed`;
- `session.started`, `session.ended`;
- `command.executed`;
- `filesystem.accessed`, `filesystem.modified`;
- `deception.triggered`, `deception.stage_changed`.

Компонент отправляет `TelemetryBatch` schema version 1 в
`POST /internal/v1/telemetry/batches`. Очередь ограничена, при переполнении
события считаются в `dropped_events` healthcheck. Неуспешные batch остаются в
очереди и повторяются; `event_id` обеспечивает дедупликацию. JSONL можно
использовать отдельно или одновременно как локальный recovery log.

Для backend:

1. Выполнить `cargo run --locked -- migrate` — миграция добавит профиль
   `pritvoryashka`, `telemetry_batches` и `attack_events`.
2. Передать backend случайный `TELEMETRY_INGEST_TOKEN` длиной не менее 32 байт
   и операторский `TELEMETRY_PUBLIC_ENDPOINT` (HTTPS, либо loopback HTTP).
3. Процесс Pritvoryashka получает значение того же токена через переменную
   `PRITVORYASHKA_TELEMETRY_TOKEN`; секрет никогда не входит в runtime JSON.
4. Создать trap с профилем `70726974-766f-4279-8000-000000000001` и ровно
   одним TCP binding. `GET /api/v1/traps/{trap_id}/runtime-config` вернёт JSON,
   который Pritvoryashka принимает напрямую.

Backend проверяет bearer token, лимиты контракта, связь trap с server, конфликт
`batch_id`/`event_id`, сохраняет received/expiry timestamps и отвечает `202`.
Владелец ловушки читает сохранённые события через JWT-защищённый
`GET /api/v1/traps/{trap_id}/events`; ingest token для чтения не принимается.

## Проверки

```sh
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# Требует разрешения на loopback TCP listener:
cargo test -p pritvoryashka --test ssh -- --ignored
```

## Осознанно не поддержано

- SFTP/SCP, X11, agent forwarding, local/remote/Unix forwarding.
- Настоящие процессы, shell grammar, pipes/redirections и host filesystem.
- Сохранение изменений VFS между сессиями.
- Автоматическое развёртывание контейнера/процесса на зарегистрированном server:
  существующий HoneyForge infrastructure executor пока не реализован.
- ClickHouse и UI-specific аналитические endpoints; события пока сохраняются
  только в PostgreSQL.

Ограничения памяти внутри процесса обеспечиваются лимитами клиентов, input,
history, event queue, event size, VFS nodes и VFS bytes. Для production также
нужно запускать процесс непривилегированным пользователем в container/systemd
с cgroup memory/CPU limits и разрешать исходящий трафик только к HoneyForge.

