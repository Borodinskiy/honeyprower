package handlers

import (
	"errors"
	"net/http"

	"honeyprower/internal/httpx"
	"honeyprower/internal/storage"
)

func (h *Handlers) ListTrapEvents(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	events, err := h.Store.ListEvents(r.Context(), id)
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
