package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"honeyprower/internal/auth"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

func setupTestHandlers() (*Handlers, *auth.Manager, *storage.Memory) {
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()
	h := New(mem, authMgr)
	return h, authMgr, mem
}

func TestTrapsHandlers(t *testing.T) {
	h, _, _ := setupTestHandlers()

	// 1. Create Trap
	body := []byte(`{"name":"SSH Trap","type":"SSH","target":"1.2.3.4:22","active":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/traps", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateTrap(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created models.Trap
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode trap: %v", err)
	}
	if created.ID != 1 || created.Name != "SSH Trap" {
		t.Fatalf("unexpected trap: %+v", created)
	}

	// 2. List Traps
	req = httptest.NewRequest(http.MethodGet, "/api/traps", nil)
	w = httptest.NewRecorder()
	h.ListTraps(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var traps []models.Trap
	if err := json.NewDecoder(w.Body).Decode(&traps); err != nil {
		t.Fatalf("decode traps: %v", err)
	}
	if len(traps) != 1 {
		t.Fatalf("expected 1 trap, got %d", len(traps))
	}

	// 3. Get Trap
	req = httptest.NewRequest(http.MethodGet, "/api/traps/1", nil)
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.GetTrap(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Update Trap
	patchBody := []byte(`{"name":"Renamed Trap"}`)
	req = httptest.NewRequest(http.MethodPatch, "/api/traps/1", bytes.NewReader(patchBody))
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.UpdateTrap(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Delete Trap
	req = httptest.NewRequest(http.MethodDelete, "/api/traps/1", nil)
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.DeleteTrap(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Get after delete -> 404
	req = httptest.NewRequest(http.MethodGet, "/api/traps/1", nil)
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.GetTrap(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestStatsHandler(t *testing.T) {
	h, _, _ := setupTestHandlers()

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	h.GetStats(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var stats models.Stats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if stats.ActiveTraps != 0 {
		t.Fatalf("expected 0 active traps, got %d", stats.ActiveTraps)
	}
}

func TestAuthHandlers(t *testing.T) {
	h, _, _ := setupTestHandlers()

	// Register
	regBody := []byte(`{"username":"admin","email":"admin@example.com","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(regBody))
	w := httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp models.AuthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode auth resp: %v", err)
	}
	if resp.Token == "" || resp.User.Username != "admin" {
		t.Fatalf("unexpected auth response: %+v", resp)
	}

	// Register duplicate
	req = httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(regBody))
	w = httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// Login with correct password
	loginBody := []byte(`{"username":"admin","password":"secretpassword"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
	w = httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Login with incorrect password
	loginBad := []byte(`{"username":"admin","password":"wrongpassword"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBad))
	w = httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEventsHandler(t *testing.T) {
	h, _, mem := setupTestHandlers()
	_, _ = mem.CreateTrap(context.Background(), models.TrapCreate{
		Name: "Trap 1", Type: "SSH", Target: "1.2.3.4:22", Active: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/traps/1/events", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	h.ListTrapEvents(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Non-existent trap
	req = httptest.NewRequest(http.MethodGet, "/api/traps/999/events", nil)
	req.SetPathValue("id", "999")
	w = httptest.NewRecorder()
	h.ListTrapEvents(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
