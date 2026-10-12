package auth

import (
	"testing"
	"time"
)

func TestAuthManager(t *testing.T) {
	mgr := NewManager()

	hash, err := mgr.HashPassword("admin")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if !mgr.CheckPassword(hash, "admin") {
		t.Fatalf("password check failed for valid password")
	}

	if mgr.CheckPassword(hash, "wrong") {
		t.Fatalf("password check succeeded for invalid password")
	}

	tok, err := mgr.CreateToken(42)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	uid, ok := mgr.UserID(tok)
	if !ok || uid != 42 {
		t.Fatalf("unexpected user id: got %d, %v, want 42, true", uid, ok)
	}

	mgr.Revoke(tok)
	_, ok = mgr.UserID(tok)
	if ok {
		t.Fatalf("expected revoked token to not be found")
	}
}

func TestSessionExpiry(t *testing.T) {
	mgr := NewManager()
	now := time.Now()
	mgr.now = func() time.Time { return now }

	tok, err := mgr.CreateToken(7)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	if _, ok := mgr.UserID(tok); !ok {
		t.Fatal("expected fresh token to be valid")
	}

	now = now.Add(SessionTTL + time.Second)
	if _, ok := mgr.UserID(tok); ok {
		t.Fatal("expected expired token to be rejected")
	}

	// новая сессия вычищает протухшие
	if _, err := mgr.CreateToken(8); err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	if _, exists := mgr.sessions[tok]; exists {
		t.Fatal("expected expired session to be pruned")
	}
}

func TestAdminSeedHash(t *testing.T) {
	mgr := NewManager()
	const seedHash = "$2a$10$wL978Q.q5X5rxRR9cjuUy.AJrhsTzZkBDt4Hi4u0NJVHdDBgpgQFu"
	if !mgr.CheckPassword(seedHash, "admin") {
		t.Fatalf("expected seed hash to match 'admin'")
	}
}
