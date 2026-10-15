# API центра

Все маршруты — на веб-адресе центра (`http://<центр>:8080`). JSON на входе и
выходе. Маршруты оператора требуют входа: `POST /api/auth/login` ставит
HttpOnly-cookie сессии на 7 дней. Запросы, меняющие данные, из браузера
проходят проверку Origin (защита от CSRF).

## Вход

| | |
|---|---|
| `POST /api/auth/login` | `{"username","password"}` |
| `POST /api/auth/register` | регистрация оператора; выключается `ALLOW_REGISTRATION=false` |
| `POST /api/auth/logout` | выход |
| `GET /api/auth/me` | текущий оператор |

## Ловушки и классы

| | |
|---|---|
| `GET /api/classes` | классы ловушек со схемами параметров (вместе со своими ловушками `plugin:<имя>`) |
| `GET /api/presets` | готовые шаблоны ловушек |
| `GET /api/traps`, `POST /api/traps` | список, создание. Параметры проверяются по схеме класса |
| `GET/PATCH/DELETE /api/traps/{id}` | ловушка. `"hostId": null` в `PATCH` — отвязать от хоста |
| `GET /api/traps/{id}/events` | события ловушки |
| `GET /api/traps/{id}/config` | `config.json` агента для этой ловушки |
| `GET /api/traps/{id}/bundle` | zip: конфиг, проекты своих ловушек, `RUN.txt` |

Порты ловушек одного хоста не должны пересекаться: при конфликте — `409`.

## Хосты

| | |
|---|---|
| `GET /api/hosts`, `POST /api/hosts` | список, создание. SSH-пароль и ключ хранятся зашифрованными (AES-256-GCM) и не возвращаются |
| `GET/PATCH/DELETE /api/hosts/{id}` | хост. Пустой пароль или ключ в `PATCH` — оставить сохранённый. `DELETE` развёрнутого хоста — `409`, пока агент не снят (или `?force=true`) |
| `POST /api/hosts/{id}/deploy` | поставить или обновить агента со всеми включёнными ловушками хоста |
| `POST /api/hosts/{id}/undeploy` | остановить агента и удалить его файлы |
| `GET /api/hosts/{id}/status` | состояние службы, слушающие порты, порты ловушек, которые не открыты |
| `GET /api/hosts/{id}/config` | `config.json` агента хоста |

## Свои ловушки

См. [plugins.md](plugins.md#api).

## События и статистика

| | |
|---|---|
| `GET /api/events` | события; фильтры `trapId`, `type`, `src` (IP), `since` (Unix-время), `limit` (по умолчанию 200) |
| `GET /api/stats` | счётчики для плиток |
| `GET /api/stats/dashboard?range=1h\|24h\|7d&tz=<минуты>` | данные графиков дашборда; `tz` — смещение от UTC, например `180` |

## Приём событий от агентов

Аутентификация — токен или ключ ловушки, не сессия оператора.

| | |
|---|---|
| `POST /cdn-cgi/rum`, `POST /v1/rgstr`, `POST /api/v2/metrics` | зашифрованный конверт (см. README). Ответ всегда `204` |
| UDP на `UDP_INGEST_ADDR` | тот же конверт, одна датаграмма — один конверт, без ответа |
| `POST /api/ingest`, `POST /api/heartbeat` | открытый JSON с заголовком `X-HF-Token` — для агентов без ключа |
