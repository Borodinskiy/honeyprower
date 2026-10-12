package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestStorageInterfaces(t *testing.T) {
	var _ Storage = (*Postgres)(nil)
	var _ Storage = (*Memory)(nil)
}

func TestFormatTS(t *testing.T) {
	if got := formatTS(0); got != "—" {
		t.Errorf("formatTS(0) = %q; want em-dash", got)
	}
	// 2024-05-20 14:30:45 UTC
	ts := float64(time.Date(2024, time.May, 20, 14, 30, 45, 0, time.UTC).Unix())
	if got := formatTS(ts); got != "2024-05-20 14:30:45" {
		t.Errorf("formatTS = %q; want 2024-05-20 14:30:45", got)
	}
}

func TestTrapStatus(t *testing.T) {
	now := time.Now()
	if got := trapStatus(nil, now); got != "never" {
		t.Errorf("nil last-seen -> %q; want never", got)
	}
	recent := now.Add(-10 * time.Second)
	if got := trapStatus(&recent, now); got != "online" {
		t.Errorf("recent -> %q; want online", got)
	}
	old := now.Add(-10 * time.Minute)
	if got := trapStatus(&old, now); got != "offline" {
		t.Errorf("old -> %q; want offline", got)
	}
}

func TestIsWarning(t *testing.T) {
	for _, tc := range []struct {
		typ  string
		want bool
	}{
		{"auth", true}, {"scan", true}, {"token", true},
		{"connect", false}, {"data", false}, {"request", false},
	} {
		if got := isWarning(tc.typ); got != tc.want {
			t.Errorf("isWarning(%q) = %v; want %v", tc.typ, got, tc.want)
		}
	}
}

func TestIsUniqueViolation(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"pgconn 23505", &pgconn.PgError{Code: "23505", Message: "duplicate key"}, true},
		{"pgconn 23503", &pgconn.PgError{Code: "23503", Message: "fk violation"}, false},
		{"text 23505", errors.New("pq: ... (23505)"), true},
		{"text duplicate", errors.New("ERROR: duplicate key value violates ..."), true},
		{"unrelated", errors.New("connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUniqueViolation(tc.err); got != tc.expected {
				t.Errorf("isUniqueViolation() = %v; want %v", got, tc.expected)
			}
		})
	}
}

func TestNewPostgresConnectionFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	dsn := "postgres://postgres:postgres@127.0.0.1:59999/honeyforge?sslmode=disable&connect_timeout=1"
	store, err := NewPostgres(ctx, dsn)
	if err == nil {
		store.Close()
		t.Fatal("expected connection error for invalid postgres host, got nil")
	}
}

func TestPostgresCloseNil(t *testing.T) {
	var p *Postgres
	if err := p.Close(); err != nil {
		t.Errorf("unexpected error on nil Postgres.Close(): %v", err)
	}
	p2 := &Postgres{}
	if err := p2.Close(); err != nil {
		t.Errorf("unexpected error on empty Postgres.Close(): %v", err)
	}
}
