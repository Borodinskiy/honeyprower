CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS traps (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    warnings INT NOT NULL DEFAULT 0,
    total_events INT NOT NULL DEFAULT 0,
    last_event_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    trap_id BIGINT NOT NULL REFERENCES traps(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    source VARCHAR(255) NOT NULL,
    time VARCHAR(100) NOT NULL,
    detail TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Логины регистронезависимы: вход ищет по LOWER(username), поэтому и уникальность должна быть по LOWER.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_key ON users (LOWER(username));

CREATE INDEX IF NOT EXISTS events_trap_id_idx ON events (trap_id);
