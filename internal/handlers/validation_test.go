package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"honeyprower/internal/httpx"
	"honeyprower/internal/router"
)

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
		{"create trap long name", "POST", "/api/traps", `{"name":"` + long + `","type":"SSH","target":"1.2.3.4:22"}`, true, http.StatusBadRequest},
		{"create trap blank name", "POST", "/api/traps", `{"name":"   ","type":"SSH","target":"1.2.3.4:22"}`, true, http.StatusBadRequest},
		{"patch trap empty target", "PATCH", "/api/traps/1", `{"target":""}`, true, http.StatusBadRequest},
		{"patch trap long type", "PATCH", "/api/traps/1", `{"type":"` + long + `"}`, true, http.StatusBadRequest},
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

	body := `{"name":"evil","type":"SSH","target":"1.2.3.4:22","active":true}`

	// Браузер с чужого сайта: cookie прикреплена, но запрос должен быть отклонён.
	req := httptest.NewRequest("POST", "http://localhost:8080/api/traps", strings.NewReader(body))
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-site POST, got %d", rec.Code)
	}

	// Тот же запрос со своей страницы проходит.
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
