package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"honeyprower/internal/auth"
	"honeyprower/internal/config"
	"honeyprower/internal/handlers"
	"honeyprower/internal/router"
	"honeyprower/internal/storage"
)

func setupTestWebMux(t *testing.T) (*http.ServeMux, *auth.Manager, string) {
	t.Helper()
	tempDir := t.TempDir()

	_ = os.WriteFile(filepath.Join(tempDir, "login.html"), []byte("<html>login</html>"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "dashboard.html"), []byte("<html>dashboard</html>"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "style.css"), []byte("/* css */"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "script.js"), []byte("// js"), 0644)

	cfg := &config.Config{
		WebAddr:   ":8080",
		APIAddr:   ":8081",
		StaticDir: tempDir,
	}
	authMgr := auth.NewManager()
	webMux := NewWebMux(cfg, authMgr, nil)

	return webMux, authMgr, tempDir
}

func TestWebRouteProtection(t *testing.T) {
	webMux, authMgr, _ := setupTestWebMux(t)

	validToken, err := authMgr.CreateToken(1)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	tests := []struct {
		name         string
		path         string
		cookieToken  string
		expectedCode int
		expectedLoc  string
	}{
		// Root path /
		{"Root unauthorized", "/", "", http.StatusFound, "/login.html"},
		{"Root authorized", "/", validToken, http.StatusFound, "/dashboard.html"},

		// /index.html
		{"Index unauthorized", "/index.html", "", http.StatusFound, "/login.html"},
		{"Index authorized", "/index.html", validToken, http.StatusFound, "/dashboard.html"},

		// /dashboard.html
		{"Dashboard unauthorized", "/dashboard.html", "", http.StatusFound, "/login.html"},
		{"Dashboard authorized", "/dashboard.html", validToken, http.StatusOK, ""},

		// /login.html
		{"Login unauthorized", "/login.html", "", http.StatusOK, ""},
		{"Login authorized", "/login.html", validToken, http.StatusFound, "/dashboard.html"},

		// Static assets
		{"Style CSS", "/style.css", "", http.StatusOK, ""},
		{"Script JS", "/script.js", "", http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.cookieToken != "" {
				req.AddCookie(&http.Cookie{
					Name:  "session_token",
					Value: tt.cookieToken,
				})
			}
			rec := httptest.NewRecorder()
			webMux.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				t.Fatalf("path %s: expected status %d, got %d", tt.path, tt.expectedCode, rec.Code)
			}
			if tt.expectedLoc != "" {
				loc := rec.Header().Get("Location")
				if loc != tt.expectedLoc {
					t.Fatalf("path %s: expected Location '%s', got '%s'", tt.path, tt.expectedLoc, loc)
				}
			}
		})
	}
}

func TestFullAuthSessionLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tempDir, "login.html"), []byte("<html>login</html>"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "dashboard.html"), []byte("<html>dashboard</html>"), 0644)

	store := storage.NewInMemory()
	storage.Seed(store)
	authMgr := auth.NewManager()
	h := handlers.New(store, authMgr)
	apiHandler := router.NewAPI(h, authMgr)

	cfg := &config.Config{
		WebAddr:   ":8080",
		APIAddr:   ":8081",
		StaticDir: tempDir,
	}
	webMux := NewWebMux(cfg, authMgr, apiHandler)

	// Step 1: Unauthorized access to / and /dashboard.html -> 302 to /login.html
	req1 := httptest.NewRequest("GET", "/", nil)
	rec1 := httptest.NewRecorder()
	webMux.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusFound || rec1.Header().Get("Location") != "/login.html" {
		t.Fatalf("expected redirect to /login.html, got %d to %s", rec1.Code, rec1.Header().Get("Location"))
	}

	reqDash1 := httptest.NewRequest("GET", "/dashboard.html", nil)
	recDash1 := httptest.NewRecorder()
	webMux.ServeHTTP(recDash1, reqDash1)
	if recDash1.Code != http.StatusFound || recDash1.Header().Get("Location") != "/login.html" {
		t.Fatalf("expected redirect to /login.html, got %d to %s", recDash1.Code, recDash1.Header().Get("Location"))
	}

	// Step 2: Login via /api/auth/login
	loginBody := `{"username":"admin","password":"admin"}`
	reqLogin := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	webMux.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("login failed: %d: %s", recLogin.Code, recLogin.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range recLogin.Result().Cookies() {
		if c.Name == "session_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("session_token cookie not found in login response")
	}

	// Step 3: Now access / and /dashboard.html with the cookie
	reqRootAuth := httptest.NewRequest("GET", "/", nil)
	reqRootAuth.AddCookie(sessionCookie)
	recRootAuth := httptest.NewRecorder()
	webMux.ServeHTTP(recRootAuth, reqRootAuth)
	if recRootAuth.Code != http.StatusFound || recRootAuth.Header().Get("Location") != "/dashboard.html" {
		t.Fatalf("expected redirect to /dashboard.html, got %d to %s", recRootAuth.Code, recRootAuth.Header().Get("Location"))
	}

	reqDashAuth := httptest.NewRequest("GET", "/dashboard.html", nil)
	reqDashAuth.AddCookie(sessionCookie)
	recDashAuth := httptest.NewRecorder()
	webMux.ServeHTTP(recDashAuth, reqDashAuth)
	if recDashAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 for dashboard.html, got %d", recDashAuth.Code)
	}

	// Step 4: Access protected API (/api/traps) with only session_token cookie (no Authorization header)
	reqTraps := httptest.NewRequest("GET", "/api/traps", nil)
	reqTraps.AddCookie(sessionCookie)
	recTraps := httptest.NewRecorder()
	webMux.ServeHTTP(recTraps, reqTraps)
	if recTraps.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/traps with cookie, got %d: %s", recTraps.Code, recTraps.Body.String())
	}

	// Step 5: Access protected API (/api/stats) with only session_token cookie
	reqStats := httptest.NewRequest("GET", "/api/stats", nil)
	reqStats.AddCookie(sessionCookie)
	recStats := httptest.NewRecorder()
	webMux.ServeHTTP(recStats, reqStats)
	if recStats.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/stats with cookie, got %d: %s", recStats.Code, recStats.Body.String())
	}

	// Step 6: Logout via /api/auth/logout with cookie
	reqLogout := httptest.NewRequest("POST", "/api/auth/logout", nil)
	reqLogout.AddCookie(sessionCookie)
	recLogout := httptest.NewRecorder()
	webMux.ServeHTTP(recLogout, reqLogout)
	if recLogout.Code != http.StatusOK && recLogout.Code != http.StatusNoContent {
		t.Fatalf("expected 200 or 204 for logout, got %d", recLogout.Code)
	}

	// Step 7: Access /dashboard.html again with old cookie -> 302 to /login.html
	reqDashAfter := httptest.NewRequest("GET", "/dashboard.html", nil)
	reqDashAfter.AddCookie(sessionCookie)
	recDashAfter := httptest.NewRecorder()
	webMux.ServeHTTP(recDashAfter, reqDashAfter)
	if recDashAfter.Code != http.StatusFound || recDashAfter.Header().Get("Location") != "/login.html" {
		t.Fatalf("expected redirect to /login.html after logout, got %d to %s", recDashAfter.Code, recDashAfter.Header().Get("Location"))
	}
}

func TestStealthRoutesInWebMux(t *testing.T) {
	store := storage.NewInMemory()
	authMgr := auth.NewManager()
	h := handlers.New(store, authMgr)
	apiHandler := router.NewAPI(h, authMgr)

	cfg := &config.Config{
		WebAddr:   ":8080",
		APIAddr:   ":8081",
		StaticDir: t.TempDir(),
	}
	webMux := NewWebMux(cfg, authMgr, apiHandler)

	stealthPaths := []string{"/cdn-cgi/rum", "/v1/rgstr", "/api/v2/metrics"}
	for _, p := range stealthPaths {
		req := httptest.NewRequest("POST", p, strings.NewReader("dummy-raw-data"))
		req.Header.Set("Content-Type", "application/octet-stream")
		rec := httptest.NewRecorder()
		webMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Errorf("expected 204 No Content for %s, got %d: %s", p, rec.Code, rec.Body.String())
		}
	}
}

// Маршруты хостов отдают SSH-доступ к серверам — без сессии оператора они закрыты.
func TestHostRoutesRequireAuth(t *testing.T) {
	store := storage.NewInMemory()
	authMgr := auth.NewManager()
	h := handlers.New(store, authMgr)
	cfg := &config.Config{StaticDir: t.TempDir()}
	webMux := NewWebMux(cfg, authMgr, router.NewAPI(h, authMgr))
	token, err := authMgr.CreateToken(1)
	if err != nil {
		t.Fatal(err)
	}

	routes := []struct{ method, path string }{
		{"GET", "/api/hosts"},
		{"POST", "/api/hosts"},
		{"GET", "/api/hosts/1"},
		{"PATCH", "/api/hosts/1"},
		{"DELETE", "/api/hosts/1"},
		{"GET", "/api/hosts/1/config"},
		{"GET", "/api/hosts/1/status"},
		{"POST", "/api/hosts/1/deploy"},
		{"POST", "/api/hosts/1/undeploy"},
	}
	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		webMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without session: %d, want 401", rt.method, rt.path, rec.Code)
		}

		req = httptest.NewRequest(rt.method, rt.path, strings.NewReader("{}"))
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		rec = httptest.NewRecorder()
		webMux.ServeHTTP(rec, req)
		// Маршрут существует: хоста 1 нет (404 с JSON) или тело неполное (400), но не 401/405.
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusMethodNotAllowed ||
			!strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s %s with session: %d %q", rt.method, rt.path, rec.Code, rec.Body.String())
		}
	}
}

func TestLoadSecretBox(t *testing.T) {
	// Из файла: создаётся при первом запуске и переживает перезапуск.
	path := filepath.Join(t.TempDir(), "data", "secret.key")
	b1, err := loadSecretBox(&config.Config{SecretKeyFile: path})
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	sealed, _ := b1.Seal("pw")
	b2, err := loadSecretBox(&config.Config{SecretKeyFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b2.Open(sealed); err != nil || got != "pw" {
		t.Fatalf("after restart: %q, %v", got, err)
	}

	// HF_SECRET_KEY важнее файла.
	b3, err := loadSecretBox(&config.Config{SecretKey: "a long enough passphrase", SecretKeyFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b3.Open(sealed); err == nil {
		t.Fatal("env key must take precedence over the key file")
	}

	if _, err := loadSecretBox(&config.Config{SecretKey: "short"}); err == nil {
		t.Fatal("weak HF_SECRET_KEY must be rejected")
	}
	// Файл ключа в недоступном месте — ошибка, а не тихий временный ключ.
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	if _, err := loadSecretBox(&config.Config{SecretKeyFile: filepath.Join(blocker, "secret.key")}); err == nil {
		t.Fatal("unwritable key path must be an error")
	}
}
