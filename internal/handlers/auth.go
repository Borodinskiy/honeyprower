package handlers

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"honeyprower/internal/auth"
	"honeyprower/internal/httpx"
	"honeyprower/internal/middleware"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

const (
	maxUsernameLen = 64
	maxEmailLen    = 255
	minPasswordLen = 6
)

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var in models.LoginRequest
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || in.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := h.Store.GetUserByUsername(r.Context(), in.Username)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if user == nil {
		// тратим то же время, что и на настоящую проверку, чтобы не выдавать существование логина
		h.Auth.SimulatePasswordCheck(in.Password)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if !h.Auth.CheckPassword(user.PasswordHash, in.Password) {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	h.startSession(w, r, user)
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	if !h.AllowRegistration {
		httpx.WriteError(w, http.StatusForbidden, "registration is disabled")
		return
	}

	var in models.RegisterRequest
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if in.Username == "" || in.Email == "" || in.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username, email and password are required")
		return
	}
	if utf8.RuneCountInString(in.Username) > maxUsernameLen {
		httpx.WriteError(w, http.StatusBadRequest, "username is too long")
		return
	}
	if len(in.Email) > maxEmailLen || !strings.Contains(in.Email, "@") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid email")
		return
	}
	if utf8.RuneCountInString(in.Password) < minPasswordLen {
		httpx.WriteError(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}
	if len(in.Password) > auth.MaxPasswordBytes {
		httpx.WriteError(w, http.StatusBadRequest, "password is too long")
		return
	}

	hash, err := h.Auth.HashPassword(in.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	user, err := h.Store.CreateUser(r.Context(), &models.User{
		Username:     in.Username,
		Email:        in.Email,
		PasswordHash: hash,
	})
	if errors.Is(err, storage.ErrAlreadyExists) {
		httpx.WriteError(w, http.StatusConflict, "username already taken")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	h.startSession(w, r, user)
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var token string
	if c, err := r.Cookie(middleware.SessionCookie); err == nil {
		token = strings.TrimSpace(c.Value)
	}
	if token == "" {
		token = middleware.BearerToken(r)
	}
	if token != "" {
		h.Auth.Revoke(token)
	}

	setSessionCookie(w, r, "", -1)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	uid, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	user, err := h.Store.GetUserByID(r.Context(), uid)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, user)
}

// startSession выдаёт токен, ставит cookie и отвечает AuthResponse.
func (h *Handlers) startSession(w http.ResponseWriter, r *http.Request, user *models.User) {
	token, err := h.Auth.CreateToken(user.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	setSessionCookie(w, r, token, int(auth.SessionTTL.Seconds()))
	httpx.WriteJSON(w, http.StatusOK, models.AuthResponse{Token: token, User: user})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.SessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// isHTTPS — запрос пришёл по TLS напрямую или через TLS-терминирующий прокси (nginx).
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
