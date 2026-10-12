package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"honeyprower/internal/httpx"
	"honeyprower/internal/middleware"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var in models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || in.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := h.Store.GetUserByUsername(r.Context(), in.Username)
	if err != nil || !h.Auth.CheckPassword(user.PasswordHash, in.Password) {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := h.Auth.CreateToken(user.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 3600,
	})
	httpx.WriteJSON(w, http.StatusOK, models.AuthResponse{Token: token, User: user})
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var in models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if in.Username == "" || in.Email == "" || in.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username, email and password are required")
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

	token, err := h.Auth.CreateToken(user.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 3600,
	})
	httpx.WriteJSON(w, http.StatusOK, models.AuthResponse{Token: token, User: user})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var token string
	if c, err := r.Cookie("session_token"); err == nil {
		token = strings.TrimSpace(c.Value)
	}
	if token == "" {
		token = middleware.BearerToken(r)
	}
	if token != "" {
		h.Auth.Revoke(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
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
