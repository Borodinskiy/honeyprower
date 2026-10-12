# Task 1: PostgreSQL Integration

/boost

## Objective
Implement PostgreSQL storage provider for Honeyforge using `pgx/v5` (`database/sql` + `github.com/jackc/pgx/v5/stdlib`), preserving the `storage.Storage` interface contract.

## Context
Working directory: `/home/tinger/honeyforge`
Existing storage interfaces are in `internal/storage/storage.go`.
Models are in `internal/models/models.go`.
Current in-memory implementation is in `internal/storage/memory.go` and `internal/storage/seed.go`.
Configuration is in `internal/config/config.go`.
Entry point is in `main.go`.

## Requirements
1. **Dependencies**:
   - Add `github.com/jackc/pgx/v5` and its stdlib driver `github.com/jackc/pgx/v5/stdlib` to `go.mod`.
   - Run `go mod tidy`.

2. **Configuration (`internal/config/config.go`)**:
   - Add `DBDSN string` to `Config` struct.
   - In `Load()`, check `DB_DSN` and `DATABASE_URL`.
   - If not set, check composite env vars: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSLMODE`.
   - Default fallback: `postgres://postgres:postgres@localhost:5432/honeyforge?sslmode=disable`.

3. **Migrations & Seed SQL Files**:
   - Create `migrations/001_schema.sql`:
     - `users` table: `id BIGSERIAL PRIMARY KEY`, `username VARCHAR(255) UNIQUE NOT NULL`, `email VARCHAR(255) NOT NULL`, `password_hash TEXT NOT NULL`, `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.
     - `traps` table: `id BIGSERIAL PRIMARY KEY`, `name VARCHAR(255) NOT NULL`, `type VARCHAR(50) NOT NULL`, `target VARCHAR(255) NOT NULL`, `active BOOLEAN NOT NULL DEFAULT TRUE`, `warnings INT NOT NULL DEFAULT 0`, `total_events INT NOT NULL DEFAULT 0`, `last_event_at TIMESTAMPTZ DEFAULT NOW()`, `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.
       *CRITICAL*: Note that `last_event_at` MUST be `TIMESTAMPTZ` (NOT VARCHAR)!
     - `events` table: `id BIGSERIAL PRIMARY KEY`, `trap_id BIGINT NOT NULL REFERENCES traps(id) ON DELETE CASCADE`, `type VARCHAR(50) NOT NULL`, `source VARCHAR(255) NOT NULL`, `time VARCHAR(100) NOT NULL`, `detail TEXT NOT NULL`, `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.
   - Create `migrations/002_seed.sql`:
     - Default `admin` user (`$2a$10$w...` bcrypt hash for password "admin", username "admin", email "admin@example.com").
     - Default traps: SSH Honeypot, Web Trap, FTP Trap.
     - Default events for traps.

4. **PostgreSQL Storage Implementation (`internal/storage/postgres.go`)**:
   - Implement `Postgres` struct satisfying `storage.Storage`:
     - `ListTraps(ctx context.Context) ([]models.Trap, error)`
     - `GetTrap(ctx context.Context, id int64) (*models.Trap, error)`
     - `CreateTrap(ctx context.Context, in models.TrapCreate) (*models.Trap, error)`
     - `UpdateTrap(ctx context.Context, id int64, patch models.TrapPatch) (*models.Trap, error)`
     - `DeleteTrap(ctx context.Context, id int64) error`
     - `ListEvents(ctx context.Context, trapID int64) ([]models.Event, error)`
     - `GetStats(ctx context.Context) (*models.Stats, error)`
     - `CreateUser(ctx context.Context, u *models.User) (*models.User, error)`
     - `GetUserByUsername(ctx context.Context, username string) (*models.User, error)`
     - `GetUserByID(ctx context.Context, id int64) (*models.User, error)`
     - `Close() error`
   - Map `sql.ErrNoRows` to `storage.ErrNotFound`.
   - Map unique constraint violation (e.g. Postgres code 23505) to `storage.ErrAlreadyExists`.
   - For `LastEventAt string` in `models.Trap`: scan `last_event_at TIMESTAMPTZ` as `sql.NullTime` or `*time.Time`. If valid, format as string (e.g., `time.RFC3339` or "2006-01-02 15:04:05"); if null, use "—".
   - `NewPostgres(ctx context.Context, dsn string) (*Postgres, error)`:
     - Open DB via `sql.Open("pgx", dsn)`.
     - Ping the database.
     - Auto-apply schema (create tables if not exist) and seed initial data if tables are empty.

5. **Wire in `main.go`**:
   - Initialize PostgreSQL:
     ```go
     store, err := storage.NewPostgres(context.Background(), cfg.DBDSN)
     if err != nil {
         log.Fatalf("failed to initialize postgres storage: %v", err)
     }
     defer store.Close()
     ```
   - Remove `storage.Seed(store)` (seeding is handled inside NewPostgres if DB is empty).

## Verification
- Code must compile with `go build -v .`.
- `go test -v ./...` must succeed.
