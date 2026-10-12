package auth

import (
	"testing"
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

func TestAdminSeedHash(t *testing.T) {
	mgr := NewManager()
	const seedHash = "$2a$10$wL978Q.q5X5rxRR9cjuUy.AJrhsTzZkBDt4Hi4u0NJVHdDBgpgQFu"
	if !mgr.CheckPassword(seedHash, "admin") {
		t.Fatalf("expected seed hash to match 'admin'")
	}
}
