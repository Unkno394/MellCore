# Локальный контур Hysteria 2 + HFSP

Это именно development-контур на одной машине. Он не использует реальный домен, VPS,
маскировку или продовые пароли.

## Топология

```text
HFSP smoke process
  | SOCKS5 UDP, 127.0.0.1:1080
Hysteria client -- QUIC + TLS --> Hysteria server, 127.0.0.1:8443
                                      |
                                      | UDP destination: 127.0.0.1:44000
                                      v
                              HFSP centre receiver
```

HFSP не знает о Hysteria: он передаёт закодированный кадр в `PacketTransport`.
`HysteriaSocks5UdpTransport` — сменный infrastructure-адаптер, реализующий этот порт
через SOCKS5 UDP ASSOCIATE. Позднее TCP/HTTPS/LoRa реализуют тот же порт без изменения
формата HFSP или core-логики.

## Запуск

Нужны `hysteria`, `openssl`, Rust/Cargo. Не запускайте эти конфиги на публичном интерфейсе.

```sh
cd deploy/local-hysteria
./generate-cert.sh
hysteria server -c server.yaml
```

В другом терминале:

```sh
cd deploy/local-hysteria
hysteria client -c client.yaml
```

В третьем терминале из корня репозитория:

```sh
cargo run -p hf-services --example hfsp_hysteria_smoke
```

Ожидаемый результат:

```text
OK: HFSP heartbeat crossed Hysteria and ACK returned through the same tunnel
```

Этот smoke-тест проверяет весь транспортный путь: TLS-сертификат доверен клиенту,
Hysteria принимает аутентификацию, SOCKS5 поддерживает UDP ASSOCIATE, HFSP кадр достигает
UDP-приёмника центра и ACK возвращается назад. Обычный HTTP/SOCKS TCP-тест этого не доказывает.

## Границы слоёв

| Слой | Ответственность |
| --- | --- |
| `hf-core` | HFSP кадр, команды, ACK/sequence и интерфейс `PacketTransport` |
| `hf-services` | UDP, Hysteria SOCKS5 UDP и будущие сменные транспорты |
| Hysteria 2 | QUIC/TLS, учётная запись агента, доставка до центра |
| `hf-center` / backend | авторизация агента, выдача/отзыв Hysteria credential, обработка HFSP |
| `hf-agent` | локальная SQLite outbox, повторная отправка до ACK, Docker-команды |

Сейчас реализованы первые три пункта и типизированные команды агента. SQLite outbox,
центральный HFSP receive loop, постоянные индивидуальные credentials и отзыв сессии —
следующий этап, их этот тест честно не эмулирует.
