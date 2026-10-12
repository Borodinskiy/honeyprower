# HoneyForge

Центр управления ловушками-приманками (honeypot): веб-панель оператора, JSON API и хранилище в PostgreSQL.
Исходная постановка задачи — `docs/project_description.pdf`.

## Архитектура

```
браузер ──► :8080 веб-сервер ──┬─ статика из Web/ (login.html, dashboard.html, script.js, style.css)
                               └─ /api/* ──reverse proxy──► 127.0.0.1:8081 API-сервер ──► PostgreSQL
```

- **Веб-сервер** (`main.go`) отдаёт фронтенд и проксирует `/api/*`. Страницы защищены на стороне сервера:
  без валидной сессии `/` и `/dashboard.html` перенаправляют на `/login.html`.
- **API-сервер** (`internal/router`, `internal/handlers`) по умолчанию слушает только `127.0.0.1` —
  снаружи он доступен лишь через прокси.
- **Хранилище** (`internal/storage`) — интерфейс `Storage`; реализации `Postgres` (рабочая) и `Memory` (для тестов).
  Схема и демо-данные (`migrations/*.sql`) применяются автоматически при старте, сид — только в пустую БД.
- **Сессии** (`internal/auth`) — случайный токен в HttpOnly-cookie `session_token`, срок жизни 7 дней.
  Хранятся в памяти процесса: после перезапуска сервера нужно войти заново.

## Запуск

### Docker Compose (весь стек)

```bash
docker compose up -d --build     # или: podman-compose up -d --build
```

Откройте http://localhost:8080 и войдите как `admin` / `admin`.

### Локально

Нужны Go 1.26+ и PostgreSQL с созданной базой `honeyforge`.

```bash
go run .
```

Либо F5 в VS Code (расширение `golang.go`), конфигурация уже есть в `.vscode/launch.json`.

## Переменные окружения

| Переменная           | По умолчанию                                                            | Назначение                                   |
|----------------------|-------------------------------------------------------------------------|----------------------------------------------|
| `WEB_ADDR`           | `:8080`                                                                 | адрес веб-сервера                             |
| `API_ADDR`           | `127.0.0.1:8081`                                                        | адрес API-сервера                             |
| `STATIC_DIR`         | `./Web`                                                                 | папка с фронтендом                            |
| `DB_DSN` / `DATABASE_URL` | —                                                                  | полная строка подключения к PostgreSQL        |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSLMODE` | `localhost`, `5432`, `postgres`, `postgres`, `honeyforge`, `disable` | используются, если DSN не задан |
| `ALLOW_REGISTRATION` | `true`                                                                  | `false` — отключить самостоятельную регистрацию |

## API

Ответы — JSON, ошибки — `{"error": "..."}`. Аутентификация: cookie `session_token`
(ставится при входе) или заголовок `Authorization: Bearer <token>` для скриптов и агентов.

| Метод  | Путь                     | Auth | Тело                          |
|--------|--------------------------|------|-------------------------------|
| POST   | `/api/auth/register`     | –    | `{username,email,password}`   |
| POST   | `/api/auth/login`        | –    | `{username,password}`         |
| POST   | `/api/auth/logout`       | –    | –                             |
| GET    | `/api/auth/me`           | ✔    | –                             |
| GET    | `/api/traps`             | ✔    | –                             |
| POST   | `/api/traps`             | ✔    | `{name,type,target,active}`   |
| GET    | `/api/traps/{id}`        | ✔    | –                             |
| PATCH  | `/api/traps/{id}`        | ✔    | любое подмножество полей      |
| DELETE | `/api/traps/{id}`        | ✔    | – (ответ 204)                 |
| GET    | `/api/traps/{id}/events` | ✔    | –                             |
| GET    | `/api/stats`             | ✔    | –                             |

Ограничения: логин до 64 символов, пароль 6–72 байта, `name`/`target` до 255 символов, `type` до 50,
тело запроса до 1 МиБ. Небезопасные запросы (POST/PATCH/DELETE) с чужого origin отклоняются с 403 (защита от CSRF).

## Тесты

```bash
go test ./...
```

Интеграционный тест PostgreSQL запускается, только если задана тестовая БД (создаёт и удаляет временную схему):

```bash
TEST_DB_DSN="postgres://postgres:postgres@localhost:5432/honeyforge?sslmode=disable" go test ./internal/storage/
```
