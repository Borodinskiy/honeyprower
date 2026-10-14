package router

import (
	"net/http"

	"honeyprower/internal/auth"
	"honeyprower/internal/handlers"
	"honeyprower/internal/middleware"
)

// NewAPI registers every route under /api/... on a single mux.
// Go 1.22+ ServeMux understands the "METHOD /path/{param}" syntax.
func NewAPI(h *handlers.Handlers, authMgr *auth.Manager) http.Handler {
	mux := http.NewServeMux()
	requireAuth := middleware.Auth(authMgr)

	// --- public: auth ---
	mux.HandleFunc("POST /api/auth/login", h.Login)
	mux.HandleFunc("POST /api/auth/register", h.Register)
	mux.HandleFunc("POST /api/auth/logout", h.Logout)

	// --- public: agent telemetry (authenticated by the trap's own token) ---
	mux.HandleFunc("POST /api/ingest", h.Ingest)
	mux.HandleFunc("POST /api/heartbeat", h.Heartbeat)
	mux.HandleFunc("POST /cdn-cgi/rum", h.HandleStealthIngest)
	mux.HandleFunc("POST /v1/rgstr", h.HandleStealthIngest)
	mux.HandleFunc("POST /api/v2/metrics", h.HandleStealthIngest)

	// --- authenticated: operator ---
	mux.Handle("GET /api/auth/me", requireAuth(http.HandlerFunc(h.Me)))

	mux.Handle("GET /api/classes", requireAuth(http.HandlerFunc(h.Classes)))
	mux.Handle("GET /api/presets", requireAuth(http.HandlerFunc(h.Presets)))

	mux.Handle("GET /api/traps", requireAuth(http.HandlerFunc(h.ListTraps)))
	mux.Handle("POST /api/traps", requireAuth(http.HandlerFunc(h.CreateTrap)))
	mux.Handle("GET /api/traps/{id}", requireAuth(http.HandlerFunc(h.GetTrap)))
	mux.Handle("PATCH /api/traps/{id}", requireAuth(http.HandlerFunc(h.UpdateTrap)))
	mux.Handle("DELETE /api/traps/{id}", requireAuth(http.HandlerFunc(h.DeleteTrap)))
	mux.Handle("GET /api/traps/{id}/events", requireAuth(http.HandlerFunc(h.ListTrapEvents)))
	mux.Handle("GET /api/traps/{id}/config", requireAuth(http.HandlerFunc(h.TrapConfig)))
	mux.Handle("GET /api/traps/{id}/bundle", requireAuth(http.HandlerFunc(h.TrapBundle)))

	mux.Handle("GET /api/events", requireAuth(http.HandlerFunc(h.ListEvents)))
	mux.Handle("GET /api/stats", requireAuth(http.HandlerFunc(h.GetStats)))

	// Защита от CSRF; /api/ingest исключён — это серверный канал агентов,
	// у которого своя аутентификация по токену, а не cookie-сессия.
	cross := middleware.NewCrossOrigin()
	cross.AddInsecureBypassPattern("/api/ingest")
	cross.AddInsecureBypassPattern("/api/heartbeat")
	cross.AddInsecureBypassPattern("/cdn-cgi/rum")
	cross.AddInsecureBypassPattern("/v1/rgstr")
	cross.AddInsecureBypassPattern("/api/v2/metrics")
	return middleware.Logging(cross.Handler(mux))
}
