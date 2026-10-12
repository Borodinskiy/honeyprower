package config

import (
	"testing"
)

func clearEnv(t *testing.T) {
	vars := []string{
		"WEB_ADDR", "API_ADDR", "STATIC_DIR",
		"DB_DSN", "DATABASE_URL",
		"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSLMODE",
	}
	for _, v := range vars {
		t.Setenv(v, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)

	cfg := Load()
	if cfg.WebAddr != ":8080" {
		t.Errorf("expected WebAddr :8080, got %s", cfg.WebAddr)
	}
	if cfg.APIAddr != ":8081" {
		t.Errorf("expected APIAddr :8081, got %s", cfg.APIAddr)
	}
	if cfg.StaticDir != "./Web" {
		t.Errorf("expected StaticDir ./Web, got %s", cfg.StaticDir)
	}
	const expectedDSN = "postgres://postgres:postgres@localhost:5432/honeyforge?sslmode=disable"
	if cfg.DBDSN != expectedDSN {
		t.Errorf("expected DBDSN %s, got %s", expectedDSN, cfg.DBDSN)
	}
}

func TestLoadDBDSN(t *testing.T) {
	clearEnv(t)
	const customDSN = "postgres://custom:pass@remote:5433/mydb?sslmode=require"
	t.Setenv("DB_DSN", customDSN)
	t.Setenv("DATABASE_URL", "postgres://ignored@localhost/test")

	cfg := Load()
	if cfg.DBDSN != customDSN {
		t.Errorf("expected DBDSN %s, got %s", customDSN, cfg.DBDSN)
	}
}

func TestLoadDatabaseURL(t *testing.T) {
	clearEnv(t)
	const customURL = "postgres://urluser:urlpass@urlhost:5432/urldb?sslmode=verify-full"
	t.Setenv("DATABASE_URL", customURL)

	cfg := Load()
	if cfg.DBDSN != customURL {
		t.Errorf("expected DBDSN %s, got %s", customURL, cfg.DBDSN)
	}
}

func TestLoadCompositeEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("DB_HOST", "db.example.com")
	t.Setenv("DB_PORT", "5439")
	t.Setenv("DB_USER", "myuser")
	t.Setenv("DB_PASSWORD", "secret")
	t.Setenv("DB_NAME", "proddb")
	t.Setenv("DB_SSLMODE", "require")

	cfg := Load()
	const expected = "postgres://myuser:secret@db.example.com:5439/proddb?sslmode=require"
	if cfg.DBDSN != expected {
		t.Errorf("expected DBDSN %s, got %s", expected, cfg.DBDSN)
	}
}
