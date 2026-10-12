# Honeypot dashboard – Go backend

## Layout
- `:8080` — static files + `/api/*` reverse proxy (open this in your browser)
- `:8081` — JSON API (called by the proxy; can be hit directly too)

## Run

```bash
# 1. put index.html, style.css, script.js into ./web/
# 2. from the project root:
go mod tidy
go run ./cmd/server
```

Open http://localhost:8080 — log in with `admin` / `admin`.

## Environment variables

| Var          | Default | Meaning                     |
|--------------|---------|-----------------------------|
| `WEB_ADDR`   | `:8080` | Static + proxy listen addr  |
| `API_ADDR`   | `:8081` | API listen addr             |
| `STATIC_DIR` | `./web` | Folder with the front files |

## API

| Method | Path                       | Auth | Body                       |
|--------|----------------------------|------|----------------------------|
| POST   | `/api/auth/register`       | –    | `{username,email,password}`|
| POST   | `/api/auth/login`          | –    | `{username,password}`      |
| GET    | `/api/auth/me`             | ✔    | –                          |
| GET    | `/api/traps`               | ✔    | –                          |
| POST   | `/api/traps`               | ✔    | `{name,type,target,active}`|
| GET    | `/api/traps/{id}`          | ✔    | –                          |
| PATCH  | `/api/traps/{id}`          | ✔    | subset of trap fields      |
| DELETE | `/api/traps/{id}`          | ✔    | – (returns 204)            |
| GET    | `/api/traps/{id}/events`   | ✔    | –                          |
| GET    | `/api/stats`               | ✔    | –                          |

Auth header: `Authorization: Bearer <token>` (the frontend already sends it).

## Replacing storage

Everything goes through `honeyprower/internal/storage.Storage`. Drop in a Postgres/SQLite
implementation, keep the method signatures, and change the single line in
`cmd/server/main.go` where `storage.NewMemory()` is called. Handlers don't change.