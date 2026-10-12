package storage

import (
	"context"
	"errors"
	"testing"

	"honeyprower/internal/models"
)

func TestMemoryStorage(t *testing.T) {
	ctx := context.Background()
	store := NewInMemory()

	// 1. Create Trap
	created, err := store.CreateTrap(ctx, models.TrapCreate{
		Name:   "Test Trap",
		Type:   "SSH",
		Target: "127.0.0.1:22",
		Active: true,
	})
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	if created.ID != 1 || created.Name != "Test Trap" || created.LastEventAt != "—" {
		t.Fatalf("unexpected created trap: %+v", created)
	}

	// 2. Get Trap
	got, err := store.GetTrap(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTrap: %v", err)
	}
	if got.ID != created.ID || got.Name != "Test Trap" {
		t.Fatalf("unexpected got trap: %+v", got)
	}

	// 3. Update Trap
	newName := "Updated Trap"
	updated, err := store.UpdateTrap(ctx, created.ID, models.TrapPatch{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateTrap: %v", err)
	}
	if updated.Name != "Updated Trap" {
		t.Fatalf("unexpected updated trap name: %s", updated.Name)
	}

	// 4. List Traps
	traps, err := store.ListTraps(ctx)
	if err != nil {
		t.Fatalf("ListTraps: %v", err)
	}
	if len(traps) != 1 || traps[0].Name != "Updated Trap" {
		t.Fatalf("unexpected traps list: %+v", traps)
	}

	// 5. Get Stats
	stats, err := store.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.ActiveTraps != 1 {
		t.Fatalf("unexpected active traps: %d", stats.ActiveTraps)
	}

	// 6. Delete Trap
	if err := store.DeleteTrap(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTrap: %v", err)
	}
	if _, err := store.GetTrap(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := store.DeleteTrap(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on deleting non-existent trap, got %v", err)
	}

	// 7. Users
	u, err := store.CreateUser(ctx, &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashed",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == 0 || u.Username != "testuser" {
		t.Fatalf("unexpected user: %+v", u)
	}

	// Duplicate user
	_, err = store.CreateUser(ctx, &models.User{
		Username: "TESTUSER",
	})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate user, got %v", err)
	}

	// Get user by username
	byName, err := store.GetUserByUsername(ctx, "TestUser")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if byName.ID != u.ID {
		t.Fatalf("unexpected user id: %d", byName.ID)
	}

	// Get user by id
	byID, err := store.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.Username != "testuser" {
		t.Fatalf("unexpected username: %s", byID.Username)
	}
}
