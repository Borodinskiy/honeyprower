package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"honeyprower/internal/models"
)

// newTestPostgres подключается к TEST_DB_DSN и работает в отдельной временной схеме,
// которая удаляется после теста. Без TEST_DB_DSN тест пропускается.
func newTestPostgres(t *testing.T) (*Postgres, string) {
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
		t.Fatalf("parse TEST_DB_DSN (must be a URL): %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	p, err := NewPostgres(ctx, u.String())
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, u.String()
}

func TestPostgresIntegration(t *testing.T) {
	p, dsn := newTestPostgres(t)
	ctx := context.Background()

	// Повторная инициализация не должна падать и дублировать сид.
	p2, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("second NewPostgres: %v", err)
	}
	_ = p2.Close()

	traps, err := p.ListTraps(ctx)
	if err != nil {
		t.Fatalf("ListTraps: %v", err)
	}
	if len(traps) != 3 {
		t.Fatalf("expected 3 seeded traps, got %d", len(traps))
	}

	admin, err := p.GetUserByUsername(ctx, "ADMIN")
	if err != nil {
		t.Fatalf("GetUserByUsername(ADMIN): %v", err)
	}
	if admin.Username != "admin" {
		t.Fatalf("unexpected user: %+v", admin)
	}

	// Логин уникален без учёта регистра.
	_, err = p.CreateUser(ctx, &models.User{Username: "Admin", Email: "x@example.com", PasswordHash: "h"})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for 'Admin', got %v", err)
	}

	// CRUD ловушки.
	created, err := p.CreateTrap(ctx, models.TrapCreate{Name: "T", Type: "SSH", Target: "10.0.0.1:22", Active: true})
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	if created.LastEventAt != "—" {
		t.Fatalf("expected no last event, got %q", created.LastEventAt)
	}
	off := false
	updated, err := p.UpdateTrap(ctx, created.ID, models.TrapPatch{Active: &off})
	if err != nil || updated.Active {
		t.Fatalf("UpdateTrap: %+v, %v", updated, err)
	}
	if _, err := p.UpdateTrap(ctx, 999999, models.TrapPatch{Active: &off}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on update, got %v", err)
	}

	stats, err := p.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.ActiveTraps != 2 || stats.Warnings24h != 229 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// Удаление ловушки каскадно удаляет её события.
	events, err := p.ListEvents(ctx, traps[0].ID)
	if err != nil || len(events) != 3 {
		t.Fatalf("ListEvents: %d, %v", len(events), err)
	}
	if err := p.DeleteTrap(ctx, traps[0].ID); err != nil {
		t.Fatalf("DeleteTrap: %v", err)
	}
	if _, err := p.ListEvents(ctx, traps[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for events of deleted trap, got %v", err)
	}
	var left int
	if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE trap_id = $1", traps[0].ID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("expected events to be cascaded, left=%d err=%v", left, err)
	}
}
