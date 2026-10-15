# Pritvoryashka

Pritvoryashka — самостоятельная Middle Interaction ловушка на Rust. Она
принимает обычные SSH-клиенты и выбранные сетевые протоколы, но никогда не запускает `/bin/sh`, команды ОС или
операции над файловой системой хоста. SSH-сессия получает виртуальный Linux-профиль или отдельный Windows-профиль;
ни один профиль не запускает команды на хосте.

## Архитектура

- `ssh/` — `russh` server, парольная авторизация, PTY, shell/exec channels,
  terminal input, таймаут и лимит параллельных клиентов.
- `protocols/` — независимые TCP listeners для Redis RESP, Docker API и HTTP,
  MySQL/PostgreSQL и FTP. Они используют виртуальные данные и создают события
  с реальным типом службы и destination port.
- `shell/` — Linux shell с профилями Ubuntu, Debian и Arch, а также отдельный
  Windows PowerShell-подобный обработчик. Оба работают только с виртуальными данными.
- `filesystem/` — нормализованные виртуальные пути, файлы, каталоги, metadata,
  права и лимиты числа/размера объектов. Доступа к host FS нет.
- `deception/` — локальный конечный автомат сценария и метрика Deception Depth.
- `telemetry/` — события контракта HoneyForge v1, монотонный `sequence_no`,
  bounded queue, batching, retry, JSONL fallback и HTTP transport.
- `integration/` — `/health/live` и `/health/ready`.

Виртуальная файловая система сохраняется в runtime-каталоге ловушки и
восстанавливается при следующем SSH-подключении. История команд тоже хранится
в этом виртуальном состоянии. Процессы и текущие сессионные сценарии остаются
в памяти; пакетные файлы и реестр установленных пакетов сохраняются.

## Управляемые приманки и виртуальные процессы

Вкладка «Приманки» хранит пользовательские объекты в конфигурации конкретной
Middle-ловушки. При запуске агент передаёт их runtime, где они применяются только к
виртуальной системе выбранного профиля. Изменение или удаление объектов в работающей ловушке
вызывает её перезапуск; открытые SSH-сессии при этом завершаются.

Артефакт задаётся `id`, `kind`, `name`, `path` и `content`. Доступны категории
учётных записей, файлов, учётных данных, баз данных, резервных копий, сетевых служб,
веб-интерфейсов, системных настроек, исходного кода, облачной инфраструктуры,
сетевых переходов, Windows-артефактов, canary-файлов и истории активности. До 32
артефактов, по 4096 байт каждый; сериализованный список ограничен 48 КиБ. Пути
для Linux ограничены виртуальными каталогами `/home/admin`, `/root`, `/tmp`, `/opt`, `/srv`,
`/var` и `/etc`; для Windows используются внутренние пути `/C/...`, отображаемые как `C:\...`. Содержимое не исполняется и не покидает виртуальную файловую систему.

`cat`, `head`, `tail` и `grep` по артефакту создают `bait.opened` с его ID, категорией,
путём и операцией. Для приманки категории `account` совпадение имени приманки с SSH
логином также создаёт событие; пароль в это событие не включается. Backend нормализует
эти события как `deception.bait_open` для графа и считает взаимодействия и сессии.

Виртуальный процесс задаётся `id`, именем, пользователем, отображаемой командой,
начальным состоянием и необязательным портом. Допускается до 24 процессов. Команда
никогда не исполняется: процессы появляются в виртуальных `ps aux`, `top`, `ss` и
`systemctl`. Порт отображается только внутри этой модели и не открывает listener на
хосте. Просмотр процесса создаёт событие с его ID. Для настоящего Windows-гостя, RDP, WinRM или HTTP-службы с сетевым обработчиком
нужна отдельная ловушка. Windows-профиль Middle пока доступен только по SSH.


## Windows-профиль Middle

При `distribution: "windows"` Middle показывает баннер `OpenSSH_for_Windows_8.1` и
виртуальный PowerShell prompt. Отдельный обработчик реализует `Get-Location`,
`Set-Location`, `Get-ChildItem`, `Get-Content`, `New-Item`, `Set-Content`,
`Add-Content`, `Remove-Item`, `Test-Path`, `Get-Process`, `Get-Service`,
`Start-Service`, `Stop-Service`, `Get-ItemProperty`, `Set-ItemProperty`,
`Write-Host`, `Join-Path`, `Get-ExecutionPolicy`, `Get-Module`, `cmd /c` и
`reg query`. Файлы и состояния служб сохраняются между интерактивными и
одноразовыми SSH-подключениями. Реестр представлен виртуальными ключами; доступ
к реестру хоста отсутствует. PowerShell/CMD хоста не запускаются. Если в образе
есть `pwsh`, синтаксис разбирает официальный `Parser.ParseInput` из PowerShell 7
в одном переиспользуемом процессе; иначе применяется ограниченный встроенный
разборщик. Исходная строка передаётся как данные и никогда не исполняется самим
`pwsh`; Rust выполняет только поддержанные команды и выражения над виртуальной
моделью. Поддерживаются присваивания, строковая интерполяция, `Join-Path`, простые
`if`-блоки и пайплайны с `Select-String`, `Sort-Object`, `Measure-Object` и
`Out-String`. Произвольные скрипты и команды вне виртуального набора отклоняются.

Windows-файлы-приманки используют пути `/C/Users/...`, `/C/Windows/...`,
`/C/Program Files/...` или `/C/ProgramData/...`; чтение через `Get-Content`
создаёт событие с ID приманки. Виртуальные Linux-пользователи в Windows-профиле
не поддерживаются. При отдельном SSH-порту Windows Middle объявляет баннер
OpenSSH for Windows. В группе Dispatcher все участники используют общий
SSH-баннер и host key; Windows Middle может делить порт с Linux Middle.

## Linux-профили уязвимостей

Поле `vulnerability_profiles` принимает `ssh_weak_credentials`,
`ssh_root_login_enabled`, `redis_unauthenticated_access`, `docker_api_exposed`,
`http_admin_panel_exposure`, `sql_database_weak_credentials`,
`ftp_anonymous_login`, `web_path_traversal` и `web_command_injection`.
SSH-профили помечают попытки входа и пишут события; принимаемые учётные данные
задаются отдельно через `ssh_auth_mode` и `ssh_credentials`.
Redis, Docker API и HTTP используют отдельные listeners; SQL поднимает MySQL и
PostgreSQL; FTP использует control и EPSV data listeners. Несколько HTTP-профилей
совместно используют один listener.

Центр проверяет, что для каждого выбранного сетевого endpoint выделена прямая
TCP-привязка. Только SSH можно направить через Dispatcher. Приложение
автоматически подбирает отдельные публичные порты для выбранных протоколов.
Настроенные файлы-приманки добавляются и в сохраняемую SSH VFS, и в виртуальные
файлы сетевых обработчиков. FTP-записи, Redis и SQL-состояние доступны сетевым
сессиям в памяти процесса; изменения файлов через FTP не переписывают SSH VFS.
Docker `create`/`exec` и Web Command Injection создают
виртуальные события и не запускают процессы. FTP EPSV data port публикуется
отдельным endpoint; передача файлов обращается только к виртуальному набору.

Профили SMB Guest, MS17-010 и BlueKeep относятся к Windows-категории и этим
Linux runtime не обслуживаются.

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

Режим SSH-авторизации задаётся `ssh_auth_mode`. По умолчанию используется
`realistic`: принимаются только точные пары из `ssh_credentials`, одинаковые для
всех IP этой ловушки. Для каждого логина задаётся только один пароль; список
должен содержать имя виртуального пользователя из `username`, остальные логины
должны быть уникальны. Если список не задан, доступны три слабые пары из примера;
можно указать от 1 до 32 собственных. Режим `adaptive` игнорирует этот список:
для каждого IP он отклоняет случайные 2–5 попыток, принимает следующую пару и
закрепляет ровно одну пару логин/пароль за IP и этой ловушкой. После этого любые
другие пары, включая другой логин, с того же IP отклоняются. Разные IP могут
закрепить разные пароли за одним виртуальным пользователем, например `root` — это
режим для сбора интерактивных сессий, а не имитация реальной базы пользователей.
Состояние хранится отдельно в runtime-каталоге каждой ловушки; одновременные
попытки сериализуются атомарной записью. Введённые пароли в телеметрию и
диагностические логи не попадают. Для отдельной
фиксированной пары можно использовать `auth.policy=configured`, `auth.username`
и `auth.password_env`; пароль передаётся только через указанную переменную окружения.

Healthcheck:

```sh
curl --fail http://127.0.0.1:9091/health/live
curl --fail http://127.0.0.1:9091/health/ready
```

## Развёртывание агентом

Агент разворачивает Middle-профиль через `DeployPritvoryashka`: генерирует
root-owned Compose-проект, отдельный runtime-каталог для SSH host key и публикует
SSH и выбранные прямые TCP endpoints. `agent_id` в runtime-конфиге берётся из локальной
зарегистрированной identity агента, а не из команды центра.

Собери образ один раз на CI/центральной машине из корня репозитория и передай
архив центру при запуске. VPS получает только уже собранный образ через первое
SSH-подключение:

```sh
docker build -f honeypots/pritvoryashka/Dockerfile -t honeyforge-pritvoryashka:local .
docker save honeyforge-pritvoryashka:local -o pritvoryashka-image.tar
HF_PRITVORYASHKA_IMAGE_ARCHIVE=pritvoryashka-image.tar hf-center ...
```

Контейнер создаёт уникальный ED25519 host key в смонтированном runtime-каталоге
при первом старте. Внешний port sharing работает через `TcpPortGroup`: у member
указывается `trap_kind: "pritvoryashka"`; отсутствующее поле сохраняет старый
вариант `kozyavka` для обратной совместимости.

Для Middle через Dispatcher агент создаёт отдельный случайный ключ на ловушку.
Dispatcher отправляет PROXY protocol v2 с адресом клиента и HMAC, а Middle
проверяет подпись только на loopback-бэкенде. На прямом публичном SSH listener
PROXY-заголовки не разбираются. Внешний клиент не может подменить адрес для
adaptive-авторизации или телеметрии.

## Команды

Поддержаны базовые `pwd`, `ls`, `cd`, `cat`, `echo`, `printf`, `whoami`, `id`,
`uname`, `hostname`, `date`, `uptime`, `df`, `du`, `free`, `file`, `lscpu`,
`env`, `printenv`, `tr`, `seq`, `wc`, `sort`, `rmdir`, `mount`, `findmnt`,
`history`, `mkdir`, `touch`, `rm`, `cp`, `mv`, `head`, `tail`, `grep`, `find`,
`test`, `clear`, `exit`, а также команды приманок:
`ps`, `top`, `kill`, `ip`, `ss`, `netstat`, `crontab`, `systemctl`,
`authorized_keys`, `docker`, `docker-compose`, `git`, `psql`, `tar`, `unzip`,
`zipinfo`, `companyctl`, `apt`, `apt-get`, `dpkg`, `which` и виртуальные
`nginx`, `redis-server`, `curl`, `vim`.

Есть одинарные/двойные кавычки, присваивания и чтение shell-переменных,
арифметическая подстановка `$((...))`, простые циклы `for`, условия `if` с
файловыми и строковыми проверками, backspace, Ctrl+C, Ctrl+D, PTY и изменение
размера терминала. Поддержаны `>`, `>>`, `|`, `&&`, `||` и `;`; конвейер
передаёт вывод следующей виртуальной команде. Подстановки команд `$(...)`,
backticks, ввод `<` и фоновые задания не поддерживаются. `apt` и
`dpkg` работают только с небольшим встроенным каталогом Ubuntu: никаких
загрузок или настоящей установки на хосте нет. Установка nginx добавляет
виртуальные файлы и службу; `sudo` проверяет виртуальное право на изменение
пакетов. `curl` отвечает только на локальный виртуальный HTTP endpoint;
интерактивное редактирование в `vim` пока недоступно. Неизвестная команда
возвращает `command not found`.

## Интерактивные приманки

Все приманки описывают один сервер приложений `billing-api` и используют одну
сессионную модель:

1. `ps`, `top`, `kill` и виртуальный `/proc` показывают процессы с PID и
   изменяемыми состояниями. `STOP`, `CONT`, `TERM` и `KILL` остаются внутри модели.
2. В VFS находятся фиктивные `.env`, deploy SSH key, AWS credentials и
   конфигурации. Они правдоподобны, но намеренно невалидны.
3. `ip`, `ss` и `netstat` показывают интерфейсы и виртуальные PostgreSQL,
   Redis, SSH и HTTP listeners.
4. `crontab`, `systemctl` и `authorized_keys` позволяют менять виртуальное
   закрепление. Доступны `crontab add` и `authorized_keys add`.
5. `docker`/`docker compose` поддерживают `ps`, `inspect`, `logs`, `exec`,
   start/stop/restart, Compose, volumes и networks.
6. `/srv/billing-api` содержит фиктивный Rust-проект с `git log`, `status`,
   `show`, `branch` и `remote -v`.
7. `psql -c <query>` имитирует схему, таблицы и ограниченные SELECT/INSERT/
   UPDATE/DELETE без настоящей СУБД.
8. `/var/backups` содержит виртуальные TAR/ZIP/SQL backup; их можно просмотреть
   и распаковать в VFS через `tar`, `unzip` и `zipinfo`.
9. `history` и `.bash_history` содержат подсказки к остальным приманкам и
   обновляются выполненными командами.
10. `companyctl` объединяет services, config и backups и меняет ту же модель.

Например, `docker stop billing-api` завершает PID 1134, удаляет его каталог из
`/proc`, обновляет `/proc/net/tcp`, убирает порт 8080 из `ss`/`netstat` и
отражается в `companyctl services list`. `docker start` восстанавливает процесс
и listener. Docker daemon, PostgreSQL, Git и процессы хоста не вызываются.

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
- `bait.opened` для чтения управляемого файла;
- `deception.triggered`, `deception.stage_changed`;
- `deception.interaction` с полями `bait`, `action`, `target`, `success` для
  успешных и неуспешных взаимодействий с приманками.

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
   SSH binding и отдельными bindings для каждого выбранного сетевого endpoint.
   `GET /api/v1/traps/{trap_id}/runtime-config` вернёт JSON,
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
- Настоящие процессы и полная совместимость со всем Bash grammar.
- Изменения виртуальных файлов и каталогов сохраняются между SSH-сессиями
  и перезапусками Middle в `virtual-filesystem.json` внутри отдельного runtime
  каталога ловушки. Хранилище ограничено лимитами VFS и записывается атомарно.
- Полный интерактивный TTY вложенных `psql`, `docker exec sh` и редактора
  `crontab -e`: вместо них поддерживаются ограниченные одношаговые команды.
- Произвольный SQL, Git plumbing и создание настоящих форматов архивов: это
  детерминированные симуляции с подготовленным набором данных.
- Автоматическое развёртывание контейнера/процесса на зарегистрированном server:
  существующий HoneyForge infrastructure executor пока не реализован.
- ClickHouse и UI-specific аналитические endpoints; события пока сохраняются
  только в PostgreSQL.

Команды Middle — только виртуальные команды из `shell/commands.rs`; они не
создают процессы ОС. Доступ к файлам идёт через виртуальную FS, ограниченную
4096 объектами, 1 MiB на файл и 4 MiB суммарно. Shell поддерживает описанный
выше безопасный набор Bash-конструкций; command substitution, ввод `<` и
фоновые задания отклоняются. SSH-сервер
ограничивает подключения, длину команды и время бездействия; агент при создании
контейнера задаёт cgroup-лимиты памяти/CPU/PID и `nofile`, read-only rootfs,
убирает capabilities и включает `no-new-privileges`. Для постоянного host key
разрешён единственный writable volume.

Контейнеры пока используют обычную Docker bridge-сеть. Вход опубликован только
на явно настроенных SSH и протокольных портах, но исходящий трафик из контейнера не ограничен
allowlist-ом HoneyForge; это остаётся отдельной задачей hardening.

