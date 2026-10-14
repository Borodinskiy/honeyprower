package router

// Инициализация обработчиков HTTP запросов по различным путям API

import (
	"net/http"

	"honeyprower/internal/auth"
	"honeyprower/internal/handlers"
	"honeyprower/internal/middleware"
)

// Регистрирует каждый маршрут по /api/... на одном serve mux.
// Начиная с Go 1.22+ ServeMux понимает формат записи в виде "METHOD /path/{param}".
// h: обработчики
func NewAPI(handlers *handlers.Handlers, authMgr *auth.Manager) http.Handler {
	mux := http.NewServeMux()
	requireAuth := middleware.Auth(authMgr)

	// --- public: обработка аутентификации ---
	mux.HandleFunc("POST /api/auth/login", handlers.Login)
	mux.HandleFunc("POST /api/auth/register", handlers.Register)
	mux.HandleFunc("POST /api/auth/logout", handlers.Logout)

	// --- public: телеметрия от агентов (агенты авторизовываются своим заранее полученным при размещении ловушки токеном) ---
	mux.HandleFunc("POST /api/ingest", handlers.Ingest)
	mux.HandleFunc("POST /api/heartbeat", handlers.Heartbeat)
	mux.HandleFunc("POST /cdn-cgi/rum", handlers.HandleStealthIngest)
	mux.HandleFunc("POST /v1/rgstr", handlers.HandleStealthIngest)
	mux.HandleFunc("POST /api/v2/metrics", handlers.HandleStealthIngest)

	// --- authenticated: оператор ---
	mux.Handle("GET /api/auth/me", requireAuth(http.HandlerFunc(handlers.Me)))

	mux.Handle("GET /api/classes", requireAuth(http.HandlerFunc(handlers.Classes)))
	mux.Handle("GET /api/presets", requireAuth(http.HandlerFunc(handlers.Presets)))

	mux.Handle("GET /api/traps", requireAuth(http.HandlerFunc(handlers.ListTraps)))
	mux.Handle("POST /api/traps", requireAuth(http.HandlerFunc(handlers.CreateTrap)))
	mux.Handle("GET /api/traps/{id}", requireAuth(http.HandlerFunc(handlers.GetTrap)))
	mux.Handle("PATCH /api/traps/{id}", requireAuth(http.HandlerFunc(handlers.UpdateTrap)))
	mux.Handle("DELETE /api/traps/{id}", requireAuth(http.HandlerFunc(handlers.DeleteTrap)))
	mux.Handle("GET /api/traps/{id}/events", requireAuth(http.HandlerFunc(handlers.ListTrapEvents)))
	mux.Handle("GET /api/traps/{id}/config", requireAuth(http.HandlerFunc(handlers.TrapConfig)))
	mux.Handle("GET /api/traps/{id}/bundle", requireAuth(http.HandlerFunc(handlers.TrapBundle)))

	mux.Handle("GET /api/events", requireAuth(http.HandlerFunc(handlers.ListEvents)))
	mux.Handle("GET /api/stats", requireAuth(http.HandlerFunc(handlers.GetStats)))

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
