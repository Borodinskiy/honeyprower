package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"honeyprower/internal/models"
)

func TestMemoryTrapsAndEvents(t *testing.T) {
	ctx := context.Background()
	store := NewInMemory()

	// Create
	created, err := store.CreateTrap(ctx, models.TrapCreate{
		Name:    "Test SSH",
		Class:   "banner",
		Bind:    "0.0.0.0",
		Port:    2222,
		Params:  json.RawMessage(`{"banner":"hi\r\n"}`),
		Enabled: true,
	}, "tok-1")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	if created.ID != 1 || created.Token != "tok-1" || created.Status != "never" {
		t.Fatalf("unexpected trap: %+v", created)
	}
	if created.LastEventAt != "—" {
		t.Fatalf("expected no last event, got %q", created.LastEventAt)
	}

	// Lookup by token (used by ingest)
	byTok, err := store.GetTrapByToken(ctx, "tok-1")
	if err != nil || byTok.ID != created.ID {
		t.Fatalf("GetTrapByToken: %+v, %v", byTok, err)
	}
	if _, err := store.GetTrapByToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown token, got %v", err)
	}

	// Insert events; one auth counts as a warning and sets trap online.
	user, pass := "root", "admin"
	if _, err := store.InsertEvent(ctx, created.ID, models.IngestEvent{
		EventType: "auth", Proto: "tcp", SrcIP: "10.0.0.9", Username: &user, Password: &pass, TS: 1700000000,
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
	if _, err := store.InsertEvent(ctx, created.ID, models.IngestEvent{
		EventType: "connect", SrcIP: "10.0.0.9", TS: 1700000001,
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}

	got, _ := store.GetTrap(ctx, created.ID)
	if got.TotalEvents != 2 || got.Warnings != 1 {
		t.Fatalf("expected 2 events / 1 warning, got %d / %d", got.TotalEvents, got.Warnings)
	}
	if got.Status != "online" {
		t.Fatalf("expected online after ingest, got %s", got.Status)
	}

	// Insert event for a missing trap -> ErrNotFound
	if _, err := store.InsertEvent(ctx, 999, models.IngestEvent{EventType: "connect"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Filter by type
	auths, err := store.ListEvents(ctx, models.EventFilter{TrapID: created.ID, EventType: "auth"})
	if err != nil || len(auths) != 1 {
		t.Fatalf("expected 1 auth event, got %d (%v)", len(auths), err)
	}
	if auths[0].Username == nil || *auths[0].Username != "root" {
		t.Fatalf("auth username lost: %+v", auths[0])
	}
	// Filter by src across all traps
	bySrc, _ := store.ListEvents(ctx, models.EventFilter{SrcIP: "10.0.0.9"})
	if len(bySrc) != 2 {
		t.Fatalf("expected 2 events by src, got %d", len(bySrc))
	}
	// Events for missing trap
	if _, err := store.ListEvents(ctx, models.EventFilter{TrapID: 999}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for events of missing trap, got %v", err)
	}

	// Update
	newName := "Renamed"
	off := false
	updated, err := store.UpdateTrap(ctx, created.ID, models.TrapPatch{Name: &newName, Enabled: &off})
	if err != nil || updated.Name != "Renamed" || updated.Enabled {
		t.Fatalf("UpdateTrap: %+v, %v", updated, err)
	}

	// Stats
	stats, _ := store.GetStats(ctx)
	if stats.ActiveTraps != 0 || stats.TotalEvents != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// Delete removes trap + events
	if err := store.DeleteTrap(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTrap: %v", err)
	}
	if _, err := store.GetTrap(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if _, err := store.GetTrapByToken(ctx, "tok-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected token gone after delete, got %v", err)
	}
	if err := store.DeleteTrap(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}
}

func TestMemoryUsers(t *testing.T) {
	ctx := context.Background()
	store := NewInMemory()

	u, err := store.CreateUser(ctx, &models.User{Username: "testuser", Email: "t@example.com", PasswordHash: "h"})
	if err != nil || u.ID == 0 {
		t.Fatalf("CreateUser: %+v, %v", u, err)
	}
	if _, err := store.CreateUser(ctx, &models.User{Username: "TESTUSER"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for case-insensitive dup, got %v", err)
	}
	byName, err := store.GetUserByUsername(ctx, "TestUser")
	if err != nil || byName.ID != u.ID {
		t.Fatalf("GetUserByUsername: %+v, %v", byName, err)
	}
	byID, err := store.GetUserByID(ctx, u.ID)
	if err != nil || byID.Username != "testuser" {
		t.Fatalf("GetUserByID: %+v, %v", byID, err)
	}
}

func TestMemoryGetTrapByKeyID(t *testing.T) {
	ctx := context.Background()
	store := NewInMemory()

	// 1. Unknown or empty keyID returns ErrNotFound
	if _, err := store.GetTrapByKeyID(ctx, "nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for nonexistent keyID, got %v", err)
	}
	if _, err := store.GetTrapByKeyID(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for empty keyID, got %v", err)
	}

	keyID := "kid-x25519-001"
	pubKey := "base64-pubkey-abc"
	privKey := "base64-privkey-xyz"

	// 2. Create trap with KeyID, PubKey, PrivKey
	created, err := store.CreateTrap(ctx, models.TrapCreate{
		Name:    "Crypto Honeypot",
		Class:   "banner",
		Bind:    "0.0.0.0",
		Port:    2222,
		KeyID:   keyID,
		PubKey:  pubKey,
		PrivKey: privKey,
		Enabled: true,
	}, "tok-crypto-1")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	if created.KeyID != keyID || created.PubKey != pubKey || created.PrivKey != privKey {
		t.Fatalf("created trap crypto fields mismatch: got keyID=%q, pubKey=%q, privKey=%q",
			created.KeyID, created.PubKey, created.PrivKey)
	}

	// 3. Successful lookup by KeyID
	got, err := store.GetTrapByKeyID(ctx, keyID)
	if err != nil {
		t.Fatalf("GetTrapByKeyID failed: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID mismatch: got %d, want %d", got.ID, created.ID)
	}
	if got.KeyID != keyID {
		t.Fatalf("KeyID mismatch: got %q, want %q", got.KeyID, keyID)
	}
	if got.PubKey != pubKey {
		t.Fatalf("PubKey mismatch: got %q, want %q", got.PubKey, pubKey)
	}
	if got.PrivKey != privKey {
		t.Fatalf("PrivKey mismatch: got %q, want %q", got.PrivKey, privKey)
	}

	// 4. Update KeyID via TrapPatch
	newKeyID := "kid-x25519-002"
	newPubKey := "base64-pubkey-new"
	newPrivKey := "base64-privkey-new"
	updated, err := store.UpdateTrap(ctx, created.ID, models.TrapPatch{
		KeyID:   &newKeyID,
		PubKey:  &newPubKey,
		PrivKey: &newPrivKey,
	})
	if err != nil {
		t.Fatalf("UpdateTrap: %v", err)
	}
	if updated.KeyID != newKeyID || updated.PubKey != newPubKey || updated.PrivKey != newPrivKey {
		t.Fatalf("updated trap fields mismatch: got %+v", updated)
	}

	// Old keyID should no longer resolve
	if _, err := store.GetTrapByKeyID(ctx, keyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for old keyID after update, got %v", err)
	}

	// New keyID resolves
	gotNew, err := store.GetTrapByKeyID(ctx, newKeyID)
	if err != nil || gotNew.ID != created.ID {
		t.Fatalf("GetTrapByKeyID after update: %+v, %v", gotNew, err)
	}

	// 5. Delete trap cleans up keyID mapping
	if err := store.DeleteTrap(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTrap: %v", err)
	}
	if _, err := store.GetTrapByKeyID(ctx, newKeyID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after DeleteTrap, got %v", err)
	}
}

func TestMemoryTrapOnlineStatus(t *testing.T) {
	ctx := context.Background()
	store := NewInMemory()

	baseTime := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	currTime := baseTime
	store.now = func() time.Time {
		return currTime
	}

	created, err := store.CreateTrap(ctx, models.TrapCreate{
		Name:    "Heartbeat Trap",
		Class:   "banner",
		Bind:    "0.0.0.0",
		Port:    8080,
		Enabled: true,
	}, "tok-online-test")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	if created.Status != "never" {
		t.Fatalf("expected initial status 'never', got %q", created.Status)
	}

	// TouchTrap records heartbeat at baseTime
	if err := store.TouchTrap(ctx, "tok-online-test"); err != nil {
		t.Fatalf("TouchTrap: %v", err)
	}

	// Immediately after heartbeat: online
	trap0, err := store.GetTrap(ctx, created.ID)
	if err != nil || trap0.Status != "online" {
		t.Fatalf("expected online at t=0, got status=%q, err=%v", trap0.Status, err)
	}

	// Age 110 seconds (< 120s): should be "online"
	currTime = baseTime.Add(110 * time.Second)
	trap110, err := store.GetTrap(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTrap at 110s: %v", err)
	}
	if trap110.Status != "online" {
		t.Fatalf("expected status 'online' at 110s age, got %q", trap110.Status)
	}

	// Age 120 seconds (boundary): should be "online"
	currTime = baseTime.Add(120 * time.Second)
	trap120, err := store.GetTrap(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTrap at 120s: %v", err)
	}
	if trap120.Status != "online" {
		t.Fatalf("expected status 'online' at 120s age, got %q", trap120.Status)
	}

	// Age 121 seconds (> 120s): should be "offline"
	currTime = baseTime.Add(121 * time.Second)
	trap121, err := store.GetTrap(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTrap at 121s: %v", err)
	}
	if trap121.Status != "offline" {
		t.Fatalf("expected status 'offline' at 121s age (> 120s), got %q", trap121.Status)
	}
}
