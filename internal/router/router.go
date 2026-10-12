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

	// --- public ---
	mux.HandleFunc("POST /api/auth/login", h.Login)
	mux.HandleFunc("POST /api/auth/register", h.Register)

	// --- authenticated ---
	mux.Handle("GET /api/auth/me", requireAuth(http.HandlerFunc(h.Me)))

	mux.Handle("GET /api/traps", requireAuth(http.HandlerFunc(h.ListTraps)))
	mux.Handle("POST /api/traps", requireAuth(http.HandlerFunc(h.CreateTrap)))
	mux.Handle("GET /api/traps/{id}", requireAuth(http.HandlerFunc(h.GetTrap)))
	mux.Handle("PATCH /api/traps/{id}", requireAuth(http.HandlerFunc(h.UpdateTrap)))
	mux.Handle("DELETE /api/traps/{id}", requireAuth(http.HandlerFunc(h.DeleteTrap)))
	mux.Handle("GET /api/traps/{id}/events", requireAuth(http.HandlerFunc(h.ListTrapEvents)))

	mux.Handle("GET /api/stats", requireAuth(http.HandlerFunc(h.GetStats)))

	// outer middleware chain
	return middleware.Logging(middleware.CORS(mux))
}
