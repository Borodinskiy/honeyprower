package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"honeyprower/internal/auth"
	"honeyprower/internal/httpx"
)

type ctxKey string

const userIDKey ctxKey = "userID"

// SessionCookie — имя cookie с токеном сессии.
const SessionCookie = "session_token"

func UserIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey).(int64)
	return id, ok
}

// Auth verifies the Bearer token or session_token cookie and puts the user id into the request context.
func Auth(mgr *auth.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := BearerToken(r)
			if tok == "" {
				if c, err := r.Cookie(SessionCookie); err == nil {
					tok = strings.TrimSpace(c.Value)
				}
			}
			if tok == "" {
				httpx.WriteError(w, http.StatusUnauthorized, "missing token")
				return
			}
			uid, ok := mgr.UserID(tok)
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey, uid)))
		})
	}
}

func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// Logging logs method, path, status, duration.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// CrossOrigin отклоняет небезопасные (POST/PATCH/DELETE) запросы, пришедшие
// из браузера с чужого origin. Это защищает cookie-сессию от CSRF.
// Запросы без браузерных заголовков (curl, агенты) пропускаются.
func CrossOrigin(next http.Handler) http.Handler {
	return http.NewCrossOriginProtection().Handler(next)
}
