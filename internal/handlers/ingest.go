package handlers

import (
	"errors"
	"net/http"
	"strings"

	"honeyprower/internal/httpx"
	"honeyprower/internal/middleware"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

// Ingest receives telemetry from an agent (FR-C3). Authentication is the trap's
// own token (header X-HF-Token or Bearer), not an operator session — the channel
// is one-way: agents only push.
func (h *Handlers) Ingest(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-HF-Token"))
	if token == "" {
		token = middleware.BearerToken(r)
	}
	if token == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "missing trap token")
		return
	}
	trap, err := h.Store.GetTrapByToken(r.Context(), token)
	if errors.Is(err, storage.ErrNotFound) {
		// 401 — агент по этому коду отбрасывает событие, а не копит его вечно.
		httpx.WriteError(w, http.StatusUnauthorized, "unknown trap token")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	var in models.IngestEvent
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	in.EventType = strings.TrimSpace(in.EventType)
	if in.EventType == "" {
		httpx.WriteError(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if _, err := h.Store.InsertEvent(r.Context(), trap.ID, in); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to store event")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
