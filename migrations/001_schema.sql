CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Логины регистронезависимы: вход ищет по LOWER(username), уникальность — тоже.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_key ON users (LOWER(username));

-- Определение ловушки: оператор создаёт его на сайте, агент запускает по нему
-- бинарник и шлёт телеметрию; связь агент→центр по token.
CREATE TABLE IF NOT EXISTS traps (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    class VARCHAR(50) NOT NULL,
    bind VARCHAR(255) NOT NULL DEFAULT '0.0.0.0',
    port INT NOT NULL DEFAULT 0,
    ports VARCHAR(255) NOT NULL DEFAULT '',
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    token TEXT UNIQUE NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    trap_id BIGINT NOT NULL REFERENCES traps(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    proto VARCHAR(16) NOT NULL DEFAULT 'tcp',
    src_ip VARCHAR(64) NOT NULL DEFAULT '',
    src_port INT NOT NULL DEFAULT 0,
    dst_port INT NOT NULL DEFAULT 0,
    session VARCHAR(64) NOT NULL DEFAULT '',
    username TEXT,
    password TEXT,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    ts DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS events_trap_id_idx ON events (trap_id);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_type_idx ON events (event_type);
CREATE INDEX IF NOT EXISTS events_src_ip_idx ON events (src_ip);
