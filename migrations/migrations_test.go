package migrations

import (
	"strings"
	"testing"
)

func TestEmbeddedMigrations(t *testing.T) {
	if SchemaSQL == "" {
		t.Fatal("SchemaSQL should not be empty")
	}
	if !strings.Contains(SchemaSQL, "CREATE TABLE IF NOT EXISTS users") {
		t.Errorf("SchemaSQL missing users table creation")
	}
	if !strings.Contains(SchemaSQL, "last_event_at TIMESTAMPTZ") {
		t.Errorf("SchemaSQL missing last_event_at TIMESTAMPTZ")
	}

	if SeedSQL == "" {
		t.Fatal("SeedSQL should not be empty")
	}
	if !strings.Contains(SeedSQL, "admin@example.com") {
		t.Errorf("SeedSQL missing admin user")
	}
	if !strings.Contains(SeedSQL, "SSH Honeypot") {
		t.Errorf("SeedSQL missing SSH Honeypot")
	}
}
