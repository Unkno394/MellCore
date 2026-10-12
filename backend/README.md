# HoneyForge Backend

Модульный Rust backend платформы honeypot-ловушек.

Самостоятельный Cargo-пакет в `backend/`. Команды ниже выполняются из этого
каталога (`cd backend` из корня репозитория). Корневой проект и отдельная
[Low-ловушка kozyavka](../honeypots/kozyavka/README.md) собираются независимо.

## Реализовано

- Axum, конфигурация, JSON-логи, graceful shutdown, единый формат ошибок.
- PostgreSQL/SQLx: миграции, пользователи, профили, аудит.
- Открытая регистрация: имя, email, пароль. Вход по email, Argon2id, Bearer JWT.
- Подтверждение email и одноразовый сброс пароля через SMTP; отзыв JWT при выходе
  и изменении аккаунта. CORS для настроенного frontend.
- Регистрация выдаёт только User. Admin управляет пользователями/профилями,
  Viewer и User читают общий каталог профилей.
- Пагинация, защита последнего Admin, проверка версии профиля, OpenAPI/Swagger.
- CRUD собственных серверов и ловушек, снимки профилей, статусы и резервирование
  портов SSH/ловушек/будущего dispatcher. Установка агента запускается через
  Center; SSH-пароль и ключ не сохраняются.
- Профиль kozyavka для существующей отдельной Low-ловушки и экспорт её конфигурации.
- Pritvoryashka: отдельная Rust Middle Interaction SSH-ловушка с виртуальным
  shell/VFS, adaptive deception и совместимой телеметрией.
- Приём телеметрии v1 в PostgreSQL с проверкой trap/server и дедупликацией.

**В этом пакете отдельно не реализованы:** WebSocket и универсальный
инфраструктурный исполнитель. SSH bootstrap агента выполняет hf-center.
INTEGRATION_MODE=mock выбирает будущий режим; MockExecutor ещё не подключён.
Режим real завершает запуск с integration_not_configured.

## Запуск

Требуется Rust 1.95+. Зависимости фиксирует Cargo.lock.

```sh
cargo run --locked
```

Без DATABASE_URL работает HTTP-каркас: liveness 200, readiness 503.
По умолчанию bind 127.0.0.1:8080. Приложение читает переменные процесса;
.env автоматически не загружает. Настройки перечислены в .env.example.

Для новой локальной БД задайте POSTGRES_PASSWORD в окружении или локальном .env:

```sh
docker compose -p honeyforge-dev up -d postgres
```

Compose создаёт PostgreSQL с собственным volume, loopback-портом 54329,
лимитом 512 MiB и одним CPU. Для уже существующей БД используйте её DATABASE_URL,
не создавайте БД заново. Для приложения задайте:

| Переменная | Локальное значение |
| --- | --- |
| DATABASE_URL | postgres://honeyforge:<URL-encoded-password>@127.0.0.1:54329/honeyforge |
| DATABASE_ALLOW_INSECURE_LOCAL | true |
| FRONTEND_URL | http://localhost:5173 (точный origin браузера) |
| JWT_SECRET | Случайный секрет не короче 32 байт, вне репозитория |

Порт Compose меняется через POSTGRES_PORT. Исключение без TLS разрешено только
для loopback PostgreSQL. Удалённые подключения проверяют сертификат и hostname;
CA задаётся параметром sslrootcert в URL. Внешний API публикуйте через HTTPS.
FRONTEND_URL — origin без пути; HTTP допустим только локально. Он используется
для CORS и ссылок писем. APP_ORIGIN сохранён как fallback, если FRONTEND_URL не задан.

Миграции применяются отдельной командой, не автоматически при запуске:

```sh
cargo run --locked -- migrate
```

Для первого Admin временно задайте BOOTSTRAP_USERNAME, BOOTSTRAP_EMAIL и
BOOTSTRAP_PASSWORD в окружении. Не передавайте пароль аргументом CLI или
строкой в истории shell.

```sh
cargo run --locked -- bootstrap-admin
```

Bootstrap разрешён, пока нет ни одного Admin, включая неактивных. Уже
зарегистрированные User не получают административных прав. Пароль: минимум
12 символов, максимум 256 UTF-8 байт. Удалите bootstrap-переменные после команды.

```sh
cargo run --locked -- serve
```

JWT_SECRET обязателен для API с PostgreSQL; migrate/bootstrap-admin/attach-email
его не требуют. Старт проверяет версии и контрольные суммы миграций. Секреты не
выводятся в SQL-логи и ошибки.

## Обновление существующей базы

Остановите старый API, сделайте резервную копию БД и выполните migrate с
существующим DATABASE_URL в согласованное окно обслуживания. Добавочные миграции:
002 — открытая авторизация, 003 — собственные серверы/ловушки/резервы портов,
004 — подтверждение email, 005 — профиль kozyavka, 006 — группы портов dispatcher,
202610110001 — профиль Pritvoryashka и хранилище телеметрии. Исходные миграции, UUID,
хеши паролей, роли, профили и аудит сохраняются.
Не пересоздавайте БД и volume.

В ходе разработки миграции проверяются только на одноразовой тестовой PostgreSQL;
на общей БД они не запускались. Существующие email остаются неподтверждёнными,
REQUIRE_EMAIL_VERIFICATION=false по умолчанию сохраняет возможность входа.

Старым аккаунтам name заполняется из username; email остаётся NULL до явной
привязки. Для старого Admin задайте LEGACY_USERNAME и LEGACY_EMAIL и выполните:

```sh
cargo run --locked -- attach-email
```

Команда работает только с аккаунтом без email, не меняет ID, пароль или роль,
отзывает прежние credentials и пишет аудит. После неё входите по email с прежним
паролем. Остальным пользователям Admin назначает email через PUT /users/{id}.
Username сохранён для административной совместимости, но для входа больше
не используется. Миграция сохраняет таблицу cookie-сессий, однако новый API
принимает только Bearer JWT: клиентам требуется новый вход. COOKIE_SECURE и
SESSION_TTL_SECONDS больше не используются.

## API

| Маршрут | Поведение |
| --- | --- |
| GET /health/live | Процесс жив, 200 |
| GET /health/ready | Management PostgreSQL доступен: 200, иначе 503 |
| POST /api/v1/auth/register | {name,email,password} → 201 User |
| POST /api/v1/auth/login | {email,password} → access_token, token_type, expires_in, user |
| POST /api/v1/auth/refresh | HttpOnly cookie → новый access_token |
| GET /api/v1/auth/me | {user} текущего JWT |
| POST /api/v1/auth/logout | Немедленный отзыв текущего JWT, 204 |
| POST /api/v1/auth/resend-verification | {email} → 202; без SMTP — 503 |
| POST /api/v1/auth/verify-email | {token} → 204 |
| POST /api/v1/auth/forgot-password | {email} → 202; без SMTP — 503 |
| POST /api/v1/auth/reset-password | {token,password} → 204 |
| /api/v1/users, /{id} | POST/GET/PUT/DELETE, только Admin |
| /api/v1/profiles, /{id} | Чтение для всех ролей, изменение только Admin |
| /api/v1/servers, /{server_id} | CRUD собственных серверов |
| /api/v1/servers/{server_id}/ports | GET резервов портов |
| /api/v1/traps, /{trap_id} | CRUD собственных экземпляров ловушек |
| /api/v1/traps/{trap_id}/runtime-config | GET JSON-конфигурации kozyavka или Pritvoryashka |
| /api/v1/traps/{trap_id}/events | GET сохранённых событий собственной ловушки по JWT |
| POST /internal/v1/telemetry/batches | Приём TelemetryBatch v1 по отдельному bearer token |
| /docs/, /openapi.json | DOCS_ENABLED=true, только loopback bind |

Авторизация API-ресурсов: `Authorization: Bearer <access_token>`. Cookie
принимается только `/auth/refresh` и `/auth/logout` с проверкой Origin; токены
в URL не принимаются. HS256, проверка срока,
issuer/audience и текущих прав в PostgreSQL. JWT sub — UUID пользователя,
jti — UUID отзываемого токена. Срок по умолчанию 15 минут, JWT_TTL_SECONDS от
60 до 3600 секунд. Токен доступа автоматически продлевается через отдельную
серверную сессию в HttpOnly/Secure/SameSite=Strict cookie, срок которой скользит
на 30 дней при использовании. Refresh-токен хранится в PostgreSQL только как
SHA-256; выход и изменение аккаунта отзывают сессию и все её JWT. Не более 10
таких сессий на аккаунт. Изменение аккаунта также отзывает
ссылки сброса/подтверждения и старые cookie-сессии. Viewer/User не читают реестр
пользователей. Admin не обходит принадлежность серверов/ловушек; Viewer их только читает.

Email: trim + ASCII lowercase, уникальность в PostgreSQL. Имя поддерживает
Unicode. Регистрация отклоняет дополнительные поля, включая role и owner_id.
Списки: `?limit=50&after=<next_cursor>`, максимум 100, сортировка по UUID.
Это не snapshot: при параллельном создании может потребоваться обновить список.
PUT пользователя заменяет username/role/is_active; password/name/email необязательны,
отсутствие или null сохраняет значение. Admin может создавать пользователей через
прежний API без email, но вход станет доступен только после назначения адреса.

PUT профиля принимает expected_version и вложенный profile:

```json
{
  "expected_version": 1,
  "profile": {
    "name": "SSH Medium",
    "description": "Cowrie profile",
    "level": "medium",
    "honeypot_type": "cowrie",
    "service_type": "ssh",
    "config": {"banner": "SSH-2.0-OpenSSH"}
  }
}
```

Устаревшая версия даёт 409. Профиль хранит JSON, но не запускает контейнер.
Очевидные секретные поля отклоняются; это ограниченная проверка, не универсальный
детектор. Настоящие credentials передаются через согласованный secret reference.

Регистрация, вход и сброс используют общий лимит 30 запросов/минуту на процесс,
Argon2 — максимум две одновременные задачи. Лимиты настраиваются; нескольким
экземплярам нужен общий rate limiter. Readiness не подтверждает наличие
ClickHouse/телеметрии; ingestion пока возвращает 404. Swagger assets встроены;
не публикуйте документацию через внешний proxy.

## Почта: подтверждение и сброс пароля

Задайте SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM и SMTP_PORT.
SMTP_TLS_MODE=implicit с портом 465 либо starttls с портом 587; сертификат
всегда проверяется. Домен и адрес отправителя задаются через переменные окружения,
секреты хранятся вне Git.
Без SMTP forgot-password и resend-verification возвращают 503 для любого адреса.
Ответ 202 одинаков для существующих, неизвестных и неактивных аккаунтов.

Письмо содержит ссылку `FRONTEND_URL/reset-password#token=...` или
`FRONTEND_URL/verify-email#token=...`; пути настраиваются FRONTEND_RESET_PATH и
FRONTEND_VERIFY_PATH. Frontend должен
прочитать fragment и отправить токен с новым паролем в API; страница frontend
не входит в этот backend. Не передавайте токен в аналитику браузера.

Токен сброса действует 30 минут, подтверждения — 24 часа. Оба одноразовые,
хранятся в БД только как SHA-256; один тип нельзя использовать вместо другого.
Повторная выдача ограничена одним письмом в минуту на аккаунт; новый токен
заменяет предыдущий. Смена пароля отзывает все JWT и ссылки сброса.
202 означает принятие в очередь, не доставку письма. Очередь в памяти ограничена
64 запросами: перезапуск может потерять ещё не отправленное письмо, тогда
повторите запрос. Ошибка SMTP аннулирует соответствующий токен; лог содержит
только request_id и факт ошибки, без адреса, токена и деталей провайдера.

Регистрация при настроенной почте ставит подтверждение в очередь; 201 означает
созданный аккаунт. User теперь содержит email_verified_at (null до подтверждения).
REQUIRE_EMAIL_VERIFICATION=true запрещает вход и использование JWT до подтверждения
(403 email_not_verified); регистрацию без почты — 503. Включайте после готовности
SMTP и страниц frontend, включая подтверждение старых аккаунтов и Admin.
По умолчанию false для совместимости. Успешное подтверждение отзывает старые JWT.

## Проверки

```sh
cargo fmt --check
cargo check --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 scripts/test_postgres.py
```

Обычные тесты не используют БД; PostgreSQL-тест отмечен ignored и запускается
последним скриптом в отдельном PostgreSQL 18 с временным хранилищем, случайными
паролем и loopback-портом. Контейнер удаляется в finally. Рабочий DATABASE_URL,
существующие volumes и серверы не используются. Docker должен быть запущен;
Cargo-зависимости уже скачаны, runner собирает offline.

Проверяются обновление старой заполненной схемы, сохранение данных, привязка
email, регистрация и гонка дубликатов, JWT, запрет назначения Admin, сброс пароля
с повторным/конкурентным использованием, отзыв/истечение, CRUD, пагинация,
версии профилей, защита последнего Admin, аудит и недоступность БД; владение
серверами/ловушками, конкуренция резервов, откат изменений, конфигурация kozyavka,
подтверждение email, разделение назначений токенов и CORS. Доставка
писем проверяется через тестовый приёмник; реальный SMTP не используется.

## Структура и следующий этап

api/ — HTTP/OpenAPI; auth.rs — пароли/JWT; password_reset.rs и email_verification.rs —
очереди одноразовых токенов; mail.rs — SMTP;
management/ — пользователи, профили, транзакции; storage.rs — PostgreSQL;
resources/ — серверы/ловушки/порты; kozyavka.rs — конфигурационный адаптер Low;
pritvoryashka.rs и runtime.rs — адаптер Middle; infrastructure.rs — будущие
интерфейсы; telemetry.rs — контракт событий; api/telemetry.rs — приём событий.

- [Архитектура](docs/architecture.md).
- [Контракт телеметрии](docs/telemetry-contract.md).
- [Граница инфраструктуры](docs/infrastructure-contract.md).
- [Контракт и сопоставление frontend](docs/frontend-integration.md).
- [Серверы и ловушки](docs/resources-api.md).
- [kozyavka](docs/kozyavka.md).
- [Pritvoryashka](../honeypots/pritvoryashka/README.md).
- [OpenAPI для frontend](docs/openapi.json).

Следующий этап: согласованные страницы frontend, настройка SMTP и инфраструктурный
адаптер. Регистрация ресурса и desired_state пока не выполняют удалённые команды.

Low находится в [honeypots/kozyavka](../honeypots/kozyavka/README.md) и остаётся
отдельной программой; её исходники не включены в пакет backend. Backend хранит профиль
kozyavka и выдаёт совместимый JSON для будущего развёртывания через инфраструктурный
адаптер. Dockerfile backend добавится на этапе контейнерного запуска.

## Установка агента через панель

В production установке backend получает `CENTER_CONTROL_TOKEN` из
`/etc/honeyforge/backend.env`. Аутентифицированный
`POST /api/v1/servers/bootstrap` принимает данные SSH только на время запроса,
сохраняет название сервера в PostgreSQL и запускает существующий SSH bootstrap
Center на `127.0.0.1:18081`. Пароль и приватный ключ в базу не записываются.
`GET /api/v1/servers/{server_id}/bootstrap` возвращает статус установки.
Перед размещением ловушки дождитесь `succeeded` и `registered: true`.
Публичный Nginx-маршрут `/v1/agents/bootstrap*` должен быть закрыт; браузер
работает только через `/api/v1/`.
