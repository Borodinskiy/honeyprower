package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"honeyprower/internal/auth"
	"honeyprower/internal/handlers"
	"honeyprower/internal/models"
	"honeyprower/internal/router"
	"honeyprower/internal/storage"
)

func setupTest(t *testing.T) (*handlers.Handlers, *auth.Manager, storage.Storage) {
	t.Helper()
	store := storage.NewInMemory()
	storage.Seed(store)
	authMgr := auth.NewManager()
	h := handlers.New(store, authMgr)
	return h, authMgr, store
}

func TestLoginCookie(t *testing.T) {
	h, _, _ := setupTest(t)

	body, _ := json.Marshal(models.LoginRequest{
		Username: "admin",
		Password: "admin",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session_token cookie was not set")
	}
	if sessionCookie.Value == "" {
		t.Fatal("session_token cookie value is empty")
	}
	if sessionCookie.Path != "/" {
		t.Fatalf("expected cookie path '/', got '%s'", sessionCookie.Path)
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("expected HttpOnly to be true")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.MaxAge != 7*24*3600 {
		t.Fatalf("expected MaxAge %d, got %d", 7*24*3600, sessionCookie.MaxAge)
	}
}

func TestRegisterCookie(t *testing.T) {
	h, _, _ := setupTest(t)

	body, _ := json.Marshal(models.RegisterRequest{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "secretpassword",
	})
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session_token cookie was not set")
	}
	if sessionCookie.Value == "" {
		t.Fatal("session_token cookie value is empty")
	}
	if sessionCookie.Path != "/" {
		t.Fatalf("expected cookie path '/', got '%s'", sessionCookie.Path)
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("expected HttpOnly to be true")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite Lax, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.MaxAge != 7*24*3600 {
		t.Fatalf("expected MaxAge %d, got %d", 7*24*3600, sessionCookie.MaxAge)
	}
}

func TestLogout(t *testing.T) {
	h, authMgr, _ := setupTest(t)

	token, err := authMgr.CreateToken(1)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Verify token is valid initially
	if _, ok := authMgr.UserID(token); !ok {
		t.Fatal("expected token to be valid initially")
	}

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: token,
	})
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("expected 200 or 204, got %d", rec.Code)
	}

	// Verify token was revoked
	if _, ok := authMgr.UserID(token); ok {
		t.Fatal("expected token to be revoked in authMgr")
	}

	// Verify cookie was cleared
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session_token cookie was not present in response")
	}
	if sessionCookie.MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge to clear cookie, got %d", sessionCookie.MaxAge)
	}
	if sessionCookie.Path != "/" {
		t.Fatalf("expected cookie path '/', got '%s'", sessionCookie.Path)
	}
}

func TestRouterLogoutEndpoint(t *testing.T) {
	h, authMgr, _ := setupTest(t)
	apiHandler := router.NewAPI(h, authMgr)

	token, _ := authMgr.CreateToken(1)

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: token,
	})
	rec := httptest.NewRecorder()

	apiHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("expected 200 or 204 from router, got %d", rec.Code)
	}
	if _, ok := authMgr.UserID(token); ok {
		t.Fatal("expected token to be revoked via router")
	}
}
