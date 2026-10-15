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
	if !strings.Contains(SchemaSQL, "CREATE TABLE IF NOT EXISTS traps") {
		t.Errorf("SchemaSQL missing traps table creation")
	}

	if SeedSQL == "" {
		t.Fatal("SeedSQL should not be empty")
	}
	if !strings.Contains(SeedSQL, "admin@example.com") {
		t.Errorf("SeedSQL missing admin user")
	}
	if !strings.Contains(SeedSQL, "banner") {
		t.Errorf("SeedSQL missing example trap")
	}
}
