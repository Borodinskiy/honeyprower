package handlers

import (
	"net/http"

	"honeyprower/internal/httpx"
)

func (h *Handlers) GetStats(w http.ResponseWriter, r *http.Request) {
	s, err := h.Store.GetStats(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load stats")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}
