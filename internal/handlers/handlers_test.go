package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

	// Create (banner class)
	body := []byte(`{"name":"SSH Trap","class":"banner","bind":"0.0.0.0","port":2222,"params":{"banner":"hi\r\n"},"enabled":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/traps", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateTrap(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created models.Trap
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID != 1 || created.Class != "banner" || created.Token == "" {
		t.Fatalf("unexpected trap: %+v", created)
	}

	// Unknown class -> 400
	req = httptest.NewRequest(http.MethodPost, "/api/traps", bytes.NewReader([]byte(`{"name":"x","class":"nope","port":1}`)))
	w = httptest.NewRecorder()
	h.CreateTrap(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown class, got %d", w.Code)
	}

	// List
	req = httptest.NewRequest(http.MethodGet, "/api/traps", nil)
	w = httptest.NewRecorder()
	h.ListTraps(w, req)
	var traps []models.Trap
	json.NewDecoder(w.Body).Decode(&traps)
	if w.Code != http.StatusOK || len(traps) != 1 {
		t.Fatalf("expected 1 trap, got %d (code %d)", len(traps), w.Code)
	}

	// Config download includes center_url + token
	req = httptest.NewRequest(http.MethodGet, "/api/traps/1/config", nil)
	req.SetPathValue("id", "1")
	req.Host = "example.test:8080"
	w = httptest.NewRecorder()
	h.TrapConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("config: expected 200, got %d", w.Code)
	}
	var cfg map[string]any
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg["center_url"] != "http://example.test:8080" || cfg["token"] != created.Token {
		t.Fatalf("unexpected config: %v", cfg)
	}

	// Bundle download is a zip
	req = httptest.NewRequest(http.MethodGet, "/api/traps/1/bundle", nil)
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.TrapBundle(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("bundle: code %d type %s", w.Code, w.Header().Get("Content-Type"))
	}

	// Update
	req = httptest.NewRequest(http.MethodPatch, "/api/traps/1", bytes.NewReader([]byte(`{"name":"Renamed","enabled":false}`)))
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.UpdateTrap(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Delete -> 204, then 404
	req = httptest.NewRequest(http.MethodDelete, "/api/traps/1", nil)
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.DeleteTrap(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/traps/1", nil)
	req.SetPathValue("id", "1")
	w = httptest.NewRecorder()
	h.GetTrap(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", w.Code)
	}
}

func createTrapReq(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/traps", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	h.CreateTrap(w, req)
	return w
}

func TestCreateTrapParamsAgainstSchema(t *testing.T) {
	h, _, _ := setupTestHandlers()

	// Кривой regex в правиле отвергается сразу, а не молча пропускается агентом.
	w := createTrapReq(t, h, `{"name":"x","class":"dialog","port":2121,"params":{"rules":[{"match":"(oops"}]}}`)
	if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte("rules[0].match")) {
		t.Fatalf("expected 400 naming rules[0].match, got %d: %s", w.Code, w.Body.String())
	}

	// Honeytoken без ID получает случайный ID.
	w = createTrapReq(t, h, `{"name":"tok","class":"honeytoken","port":8088,"params":{"tokens":[{"label":"share/x","token":""}]}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("honeytoken: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var ht models.Trap
	json.NewDecoder(w.Body).Decode(&ht)
	var hp struct {
		Tokens []map[string]string `json:"tokens"`
	}
	json.Unmarshal(ht.Params, &hp)
	if len(hp.Tokens) != 1 || len(hp.Tokens[0]["token"]) < 8 || hp.Tokens[0]["kind"] != "url" {
		t.Fatalf("expected generated token, got %+v", hp.Tokens)
	}

	// params.ports у многопортового класса переезжает в поле ловушки.
	w = createTrapReq(t, h, `{"name":"scan","class":"port_listener","params":{"ports":"9000-9002","action":"close"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("port_listener: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var pl models.Trap
	json.NewDecoder(w.Body).Decode(&pl)
	if pl.Ports != "9000-9002" || bytes.Contains(pl.Params, []byte("ports")) {
		t.Fatalf("ports not moved: ports=%q params=%s", pl.Ports, pl.Params)
	}

	// PATCH параметров проверяется по схеме класса этой ловушки (honeytoken).
	path := "/api/traps/" + strconv.FormatInt(ht.ID, 10)
	req := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader([]byte(`{"params":{"tokens":"nope"}}`)))
	req.SetPathValue("id", strconv.FormatInt(ht.ID, 10))
	w = httptest.NewRecorder()
	h.UpdateTrap(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad patch params, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/traps/999", bytes.NewReader([]byte(`{"params":{}}`)))
	req.SetPathValue("id", "999")
	w = httptest.NewRecorder()
	h.UpdateTrap(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing trap, got %d", w.Code)
	}
}

func TestClassesAndPresets(t *testing.T) {
	h, _, _ := setupTestHandlers()

	req := httptest.NewRequest(http.MethodGet, "/api/classes", nil)
	w := httptest.NewRecorder()
	h.Classes(w, req)
	var classes []map[string]any
	json.NewDecoder(w.Body).Decode(&classes)
	if w.Code != http.StatusOK || len(classes) < 5 {
		t.Fatalf("expected class catalog, got %d classes (code %d)", len(classes), w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/presets", nil)
	w = httptest.NewRecorder()
	h.Presets(w, req)
	var presets []map[string]any
	json.NewDecoder(w.Body).Decode(&presets)
	if w.Code != http.StatusOK || len(presets) == 0 {
		t.Fatalf("expected presets, got %d (code %d)", len(presets), w.Code)
	}
}

func TestIngestFlow(t *testing.T) {
	h, _, mem := setupTestHandlers()
	trap, _ := mem.CreateTrap(nil, models.TrapCreate{Name: "T", Class: "banner", Port: 2222}, "tok-xyz")

	// Valid ingest
	ev := []byte(`{"trap_class":"banner","event_type":"auth","src_ip":"1.2.3.4","username":"root","password":"x","ts":1700000000}`)
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(ev))
	req.Header.Set("X-HF-Token", "tok-xyz")
	w := httptest.NewRecorder()
	h.Ingest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("ingest: expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Wrong token -> 401
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(ev))
	req.Header.Set("X-HF-Token", "nope")
	w = httptest.NewRecorder()
	h.Ingest(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", w.Code)
	}

	// Missing token -> 401
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(ev))
	w = httptest.NewRecorder()
	h.Ingest(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", w.Code)
	}

	// The event landed and is filterable.
	req = httptest.NewRequest(http.MethodGet, "/api/events?type=auth", nil)
	w = httptest.NewRecorder()
	h.ListFilterEvents(w, req)
	var events []models.Event
	json.NewDecoder(w.Body).Decode(&events)
	if w.Code != http.StatusOK || len(events) != 1 || *events[0].Username != "root" {
		t.Fatalf("expected 1 auth event, got %d (code %d)", len(events), w.Code)
	}
	_ = trap
}

func TestHeartbeat(t *testing.T) {
	h, _, mem := setupTestHandlers()
	mem.CreateTrap(nil, models.TrapCreate{Name: "T", Class: "banner", Port: 2222}, "tok-hb")

	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
	req.Header.Set("X-HF-Token", "tok-hb")
	w := httptest.NewRecorder()
	h.Heartbeat(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: expected 204, got %d", w.Code)
	}
	// Trap is now online.
	trap, _ := mem.GetTrapByToken(nil, "tok-hb")
	if trap.Status != "online" {
		t.Fatalf("expected online after heartbeat, got %s", trap.Status)
	}

	// Unknown token -> 401
	req = httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
	req.Header.Set("X-HF-Token", "nope")
	w = httptest.NewRecorder()
	h.Heartbeat(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", w.Code)
	}
}

func TestStatsHandler(t *testing.T) {
	h, _, _ := setupTestHandlers()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	h.GetStats(w, req)
	var stats models.Stats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if w.Code != http.StatusOK || stats.ActiveTraps != 0 {
		t.Fatalf("unexpected stats: %+v (code %d)", stats, w.Code)
	}
}

func TestEventsHandler(t *testing.T) {
	h, _, mem := setupTestHandlers()
	trap, _ := mem.CreateTrap(nil, models.TrapCreate{Name: "T1", Class: "banner", Port: 2222}, "tok-ev")

	req := httptest.NewRequest(http.MethodGet, "/api/traps/1/events", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	h.ListTrapEvents(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/traps/999/events", nil)
	req.SetPathValue("id", "999")
	w = httptest.NewRecorder()
	h.ListTrapEvents(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	_ = trap
}

func TestAuthHandlers(t *testing.T) {
	h, _, _ := setupTestHandlers()

	regBody := []byte(`{"username":"admin","email":"admin@example.com","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(regBody))
	w := httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp models.AuthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" || resp.User.Username != "admin" {
		t.Fatalf("unexpected auth response: %+v", resp)
	}

	// Duplicate
	req = httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(regBody))
	w = httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}

	// Correct login
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"username":"admin","password":"secretpassword"}`)))
	w = httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", w.Code)
	}

	// Wrong password
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"username":"admin","password":"wrong"}`)))
	w = httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
