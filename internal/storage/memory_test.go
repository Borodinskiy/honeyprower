package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

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
