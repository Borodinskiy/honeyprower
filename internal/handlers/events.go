package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

// ListTrapEvents handles GET /api/traps/{id}/events.
func (h *Handlers) ListTrapEvents(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	f := models.EventFilter{TrapID: id, Limit: queryInt(r, "limit", 200)}
	events, err := h.Store.ListEvents(r.Context(), f)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load events")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, events)
}

// ListEvents handles GET /api/events with filters (FR-C4): trapId, type, src, since, limit.
func (h *Handlers) ListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := models.EventFilter{
		EventType: q.Get("type"),
		SrcIP:     q.Get("src"),
		Limit:     queryInt(r, "limit", 200),
	}
	if v := q.Get("trapId"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.TrapID = id
		}
	}
	if v := q.Get("since"); v != "" {
		if ts, err := strconv.ParseFloat(v, 64); err == nil {
			f.SinceTS = ts
		}
	}
	events, err := h.Store.ListEvents(r.Context(), f)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load events")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, events)
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
