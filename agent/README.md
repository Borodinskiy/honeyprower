# HoneyForge Agent

Low-interaction honeypot на Rust. Собирается в один бинарник. Конфиг едет
вместе с бинарником (JSON-файл рядом); из центра ничего не приходит — канал
односторонний, агент только шлёт телеметрию. Поменять ловушку = поправить
конфиг и запустить заново.

## Сборка

```bash
cargo build --release          # target/release/honeyforge-agent
```

## Запуск

```bash
honeyforge-agent [config.json]         # по умолчанию ./config.json или $HF_CONFIG
```

Конфиг и готовую команду запуска выдаёт центр при создании ловушки на сайте.

## Классы ловушек

| class           | что эмулирует                                              |
|-----------------|-----------------------------------------------------------|
| `port_listener` | открытые порты + детектор сканирования                    |
| `banner`        | статический баннер сервиса (SSH/FTP/SMTP…)                |
| `dialog`        | текстовый протокол по regex-правилам (FTP/SMTP/POP3/Redis)|
| `http`          | HTTP-приманка: маршруты, ловля логинов из форм/Basic      |
| `tarpit`        | удержание клиента (endlessh-подобный)                     |
| `honeytoken`    | HTTP-приёмник ссылок-приманок                             |
| `udp`           | UDP-ответчик: DNS/NTP/SSDP/SIP или правила                |

## Формат конфига

```json
{
  "center_url": "http://127.0.0.1:8080",
  "token": "<токен ловушки из центра>",
  "trap": {
    "class": "banner",
    "bind": "0.0.0.0",
    "port": 2222,
    "params": { "banner": "SSH-2.0-OpenSSH_8.9p1\r\n", "close_after_input": true }
  }
}
```

События уходят POST'ом на `{center_url}/api/ingest` с заголовком `X-HF-Token`.
При недоступности центра события буферизуются в `<config>.buffer` и досылаются.

## Тесты

```bash
cargo test
```
