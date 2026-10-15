package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/router"
)

func modelsTrap() models.TrapCreate {
	return models.TrapCreate{Name: "T", Class: "banner", Bind: "0.0.0.0", Port: 2222}
}

func TestInputValidation(t *testing.T) {
	h, authMgr, _ := setupTest(t)
	api := router.NewAPI(h, authMgr)
	token, _ := authMgr.CreateToken(1)

	long := strings.Repeat("a", 300)
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		auth   bool
		want   int
	}{
		{"register short password", "POST", "/api/auth/register", `{"username":"u1","email":"u1@example.com","password":"123"}`, false, http.StatusBadRequest},
		{"register password over 72 bytes", "POST", "/api/auth/register", `{"username":"u1","email":"u1@example.com","password":"` + strings.Repeat("p", 73) + `"}`, false, http.StatusBadRequest},
		{"register long username", "POST", "/api/auth/register", `{"username":"` + long + `","email":"u1@example.com","password":"secret1"}`, false, http.StatusBadRequest},
		{"register bad email", "POST", "/api/auth/register", `{"username":"u1","email":"nope","password":"secret1"}`, false, http.StatusBadRequest},
		{"register case-insensitive duplicate", "POST", "/api/auth/register", `{"username":"ADMIN","email":"a@example.com","password":"secret1"}`, false, http.StatusConflict},
		{"login unknown user", "POST", "/api/auth/login", `{"username":"ghost","password":"whatever"}`, false, http.StatusUnauthorized},
		{"create trap unknown class", "POST", "/api/traps", `{"name":"t","class":"nope","port":2222}`, true, http.StatusBadRequest},
		{"create trap missing name", "POST", "/api/traps", `{"name":"  ","class":"banner","port":2222}`, true, http.StatusBadRequest},
		{"create trap bad port", "POST", "/api/traps", `{"name":"t","class":"banner","port":0}`, true, http.StatusBadRequest},
		{"create multiport without ports", "POST", "/api/traps", `{"name":"t","class":"port_listener","ports":""}`, true, http.StatusBadRequest},
		{"create trap params not object", "POST", "/api/traps", `{"name":"t","class":"banner","port":2222,"params":[1,2]}`, true, http.StatusBadRequest},
		{"patch trap bad port", "PATCH", "/api/traps/1", `{"port":99999}`, true, http.StatusBadRequest},
		{"body too large", "POST", "/api/traps", `{"name":"` + strings.Repeat("a", httpx.MaxBodyBytes) + `"}`, true, http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.auth {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d: %s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRegistrationDisabled(t *testing.T) {
	h, authMgr, _ := setupTest(t)
	h.AllowRegistration = false
	api := router.NewAPI(h, authMgr)

	req := httptest.NewRequest("POST", "/api/auth/register",
		strings.NewReader(`{"username":"u1","email":"u1@example.com","password":"secret1"}`))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCrossOriginRequestRejected(t *testing.T) {
	h, authMgr, _ := setupTest(t)
	api := router.NewAPI(h, authMgr)
	token, _ := authMgr.CreateToken(1)

	body := `{"name":"evil","class":"banner","port":2222,"params":{"banner":"x"}}`

	// Cross-site browser POST with cookie must be rejected.
	req := httptest.NewRequest("POST", "http://localhost:8080/api/traps", strings.NewReader(body))
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-site POST, got %d", rec.Code)
	}

	// Same-origin passes.
	req = httptest.NewRequest("POST", "http://localhost:8080/api/traps", strings.NewReader(body))
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for same-origin POST, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIngestBypassesCrossOrigin(t *testing.T) {
	h, authMgr, store := setupTest(t)
	api := router.NewAPI(h, authMgr)
	trap, _ := store.CreateTrap(nil, modelsTrap(), "tok-ing")

	// Agent POST from "cross-site" (no browser) must be allowed through to ingest.
	ev := `{"trap_class":"banner","event_type":"connect","src_ip":"9.9.9.9","ts":1700000000}`
	req := httptest.NewRequest("POST", "http://localhost:8080/api/ingest", strings.NewReader(ev))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("X-HF-Token", "tok-ing")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for agent ingest, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = trap
}
