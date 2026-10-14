package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"honeyprower/internal/models"
)

// newTestPostgres connects to TEST_DB_DSN in its own temporary schema, dropped
// after the test. Without TEST_DB_DSN the test is skipped.
func newTestPostgres(t *testing.T) (*Postgres, string) {
	t.Helper()
	dsn, _ := newTestSchema(t)
	p, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, dsn
}

// newTestSchema creates an empty temporary schema and returns a DSN pointing at
// it plus a connection already bound to it.
func newTestSchema(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set, skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	schema := fmt.Sprintf("hf_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse TEST_DB_DSN: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	conn, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatalf("open schema conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return u.String(), conn
}

func TestPostgresIntegration(t *testing.T) {
	p, dsn := newTestPostgres(t)
	ctx := context.Background()

	// Re-init must be idempotent (no duplicate seed).
	p2, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("second NewPostgres: %v", err)
	}
	_ = p2.Close()

	// Seed has admin user + demo traps.
	admin, err := p.GetUserByUsername(ctx, "ADMIN")
	if err != nil || admin.Username != "admin" {
		t.Fatalf("seed admin: %+v, %v", admin, err)
	}
	traps, err := p.ListTraps(ctx)
	if err != nil || len(traps) != 5 {
		t.Fatalf("expected 5 seeded traps, got %d (%v)", len(traps), err)
	}
	if traps[0].Class != "banner" || traps[0].Status != "never" {
		t.Fatalf("unexpected seeded trap: %+v", traps[0])
	}
	if traps[1].Class != "dialog" {
		t.Fatalf("expected second seeded trap to be dialog, got %+v", traps[1])
	}

	// Create a trap and ingest events against it.
	created, err := p.CreateTrap(ctx, models.TrapCreate{
		Name: "FTP", Class: "dialog", Bind: "0.0.0.0", Port: 2121,
		Params: json.RawMessage(`{"greeting":"220 ok\r\n"}`), Enabled: true,
	}, "tok-pg-1")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	if created.LastEventAt != "—" {
		t.Fatalf("expected no last event, got %q", created.LastEventAt)
	}

	// Duplicate token -> ErrAlreadyExists
	if _, err := p.CreateTrap(ctx, models.TrapCreate{Name: "x", Class: "banner", Port: 1}, "tok-pg-1"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for dup token, got %v", err)
	}

	byTok, err := p.GetTrapByToken(ctx, "tok-pg-1")
	if err != nil || byTok.ID != created.ID {
		t.Fatalf("GetTrapByToken: %+v, %v", byTok, err)
	}

	user, pass := "root", "toor"
	for _, ev := range []models.IngestEvent{
		{EventType: "connect", SrcIP: "203.0.113.5", TS: 1700000000},
		{EventType: "auth", SrcIP: "203.0.113.5", Username: &user, Password: &pass, TS: float64(time.Now().Unix())},
	} {
		if _, err := p.InsertEvent(ctx, created.ID, ev); err != nil {
			t.Fatalf("InsertEvent: %v", err)
		}
	}
	if _, err := p.InsertEvent(ctx, 999999, models.IngestEvent{EventType: "connect"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound ingesting to missing trap, got %v", err)
	}

	got, _ := p.GetTrap(ctx, created.ID)
	if got.TotalEvents != 2 || got.Warnings != 1 || got.Status != "online" {
		t.Fatalf("derived fields wrong: events=%d warnings=%d status=%s", got.TotalEvents, got.Warnings, got.Status)
	}

	// Filter events
	auths, err := p.ListFilterEvents(ctx, models.EventFilter{TrapID: created.ID, EventType: "auth"})
	if err != nil || len(auths) != 1 || auths[0].Username == nil || *auths[0].Username != "root" {
		t.Fatalf("auth filter: %+v, %v", auths, err)
	}
	bySrc, _ := p.ListFilterEvents(ctx, models.EventFilter{SrcIP: "203.0.113.5"})
	if len(bySrc) != 2 {
		t.Fatalf("expected 2 by src, got %d", len(bySrc))
	}

	stats, _ := p.GetStats(ctx)
	if stats.TotalEvents != 2 || stats.Warnings24h != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// Delete cascades events.
	if err := p.DeleteTrap(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTrap: %v", err)
	}
	if _, err := p.ListFilterEvents(ctx, models.EventFilter{TrapID: created.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for events of deleted trap, got %v", err)
	}
	var left int
	if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE trap_id = $1", created.ID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("expected cascaded events, left=%d err=%v", left, err)
	}
}

// Базы, созданные до появления хостов: при старте центра у traps появляется
// host_id, старые ловушки остаются без хоста и не теряют событий.
func TestPostgresUpgradesSchemaWithoutHosts(t *testing.T) {
	dsn, conn := newTestSchema(t)
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE users (
			id BIGSERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, email VARCHAR(255) NOT NULL,
			password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
		CREATE TABLE traps (
			id BIGSERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, class VARCHAR(50) NOT NULL,
			bind VARCHAR(255) NOT NULL DEFAULT '0.0.0.0', port INT NOT NULL DEFAULT 0,
			ports VARCHAR(255) NOT NULL DEFAULT '', params JSONB NOT NULL DEFAULT '{}'::jsonb,
			token TEXT UNIQUE NOT NULL, key_id VARCHAR(16) NOT NULL DEFAULT '', pub_key TEXT NOT NULL DEFAULT '',
			priv_key TEXT NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT TRUE,
			last_seen TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
		CREATE TABLE events (
			id BIGSERIAL PRIMARY KEY, trap_id BIGINT NOT NULL REFERENCES traps(id) ON DELETE CASCADE,
			event_type VARCHAR(50) NOT NULL, proto VARCHAR(16) NOT NULL DEFAULT 'tcp',
			src_ip VARCHAR(64) NOT NULL DEFAULT '', src_port INT NOT NULL DEFAULT 0, dst_port INT NOT NULL DEFAULT 0,
			session VARCHAR(64) NOT NULL DEFAULT '', username TEXT, password TEXT,
			data JSONB NOT NULL DEFAULT '{}'::jsonb, ts DOUBLE PRECISION NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
		INSERT INTO traps (name, class, port, token) VALUES ('old', 'banner', 2222, 'tok-old');
		INSERT INTO events (trap_id, event_type, ts) VALUES (1, 'connect', 1700000000);
	`); err != nil {
		t.Fatalf("create old schema: %v", err)
	}

	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgres on old schema: %v", err)
	}
	defer p.Close()

	old, err := p.GetTrapByToken(ctx, "tok-old")
	if err != nil || old.HostID != nil || old.TotalEvents != 1 {
		t.Fatalf("old trap after upgrade: %+v, %v", old, err)
	}
	// Непустая база не засеивается заново.
	if traps, _ := p.ListTraps(ctx); len(traps) != 1 {
		t.Fatalf("seed must not run on an existing database, traps=%d", len(traps))
	}
	h, err := p.CreateHost(ctx, models.Host{Name: "h", Address: "10.1.1.1", SSHPort: 22, Username: "root", AuthType: "password"})
	if err != nil {
		t.Fatalf("CreateHost after upgrade: %v", err)
	}
	moved, err := p.UpdateTrap(ctx, old.ID, models.TrapPatch{HostID: models.OptionalID{Set: true, ID: &h.ID}})
	if err != nil || moved.HostID == nil || *moved.HostID != h.ID {
		t.Fatalf("assign old trap to host: %+v, %v", moved, err)
	}
}
