package handlers

import (
	"errors"
	"net/http"
	"strings"

	"honeyprower/internal/httpx"
	"honeyprower/internal/middleware"
	"honeyprower/internal/storage"
)

// Heartbeat refreshes a trap's last-seen so the dashboard can show it online
// even between attacks (FR-A3 periodic telemetry). Auth is the trap token.
func (h *Handlers) Heartbeat(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-HF-Token"))
	if token == "" {
		token = middleware.BearerToken(r)
	}
	if token == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "missing trap token")
		return
	}
	if err := h.Store.TouchTrap(r.Context(), token); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			httpx.WriteError(w, http.StatusUnauthorized, "unknown trap token")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "heartbeat failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
