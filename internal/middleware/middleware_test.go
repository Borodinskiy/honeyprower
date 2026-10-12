package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"honeyprower/internal/auth"
	"honeyprower/internal/middleware"
)

func TestAuthMiddleware(t *testing.T) {
	mgr := auth.NewManager()
	token, err := mgr.CreateToken(42)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	handler := middleware.Auth(mgr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := middleware.UserIDFromContext(r.Context())
		if !ok || uid != 42 {
			http.Error(w, "bad user", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: Bearer token header
	t.Run("Bearer token header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	// Case 2: session_token cookie when header is absent
	t.Run("session_token cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_token",
			Value: token,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	// Case 3: Bearer token priority over cookie
	t.Run("Bearer token priority over cookie", func(t *testing.T) {
		token2, _ := mgr.CreateToken(99)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token) // user 42
		req.AddCookie(&http.Cookie{
			Name:  "session_token",
			Value: token2, // user 99
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 (user 42), got %d", rec.Code)
		}
	})

	// Case 4: Missing token
	t.Run("Missing token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	// Case 5: Invalid token
	t.Run("Invalid token in cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_token",
			Value: "non-existent-token",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}
