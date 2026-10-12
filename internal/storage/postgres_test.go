package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestStorageInterfaces(t *testing.T) {
	var _ Storage = (*Postgres)(nil)
	var _ Storage = (*Memory)(nil)
}

func TestFormatLastEvent(t *testing.T) {
	// Null time should return em-dash
	nullTime := sql.NullTime{Valid: false}
	if got := formatLastEvent(nullTime); got != "—" {
		t.Errorf("formatLastEvent(invalid) = %q; want \"—\"", got)
	}

	// Valid time should return formatted string "YYYY-MM-DD HH:MM:SS"
	fixedTime := time.Date(2024, time.May, 20, 14, 30, 45, 0, time.UTC)
	validTime := sql.NullTime{Time: fixedTime, Valid: true}
	want := "2024-05-20 14:30:45"
	if got := formatLastEvent(validTime); got != want {
		t.Errorf("formatLastEvent(valid) = %q; want %q", got, want)
	}
}

func TestIsUniqueViolation(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name: "pgconn PgError 23505",
			err: &pgconn.PgError{
				Code:    "23505",
				Message: "duplicate key value violates unique constraint",
			},
			expected: true,
		},
		{
			name: "pgconn PgError foreign key violation 23503",
			err: &pgconn.PgError{
				Code:    "23503",
				Message: "foreign key violation",
			},
			expected: false,
		},
		{
			name:     "standard error with 23505 in text",
			err:      errors.New("pq: duplicate key value violates unique constraint (23505)"),
			expected: true,
		},
		{
			name:     "standard error with duplicate key value",
			err:      errors.New("ERROR: duplicate key value violates unique constraint \"users_username_key\""),
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"),
			expected: false,
		},
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

	// Connect to non-listening port with immediate timeout
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
