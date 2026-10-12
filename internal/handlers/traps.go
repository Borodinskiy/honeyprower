package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

func (h *Handlers) ListTraps(w http.ResponseWriter, r *http.Request) {
	traps, err := h.Store.ListTraps(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load traps")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, traps)
}

func (h *Handlers) CreateTrap(w http.ResponseWriter, r *http.Request) {
	var in models.TrapCreate
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Name == "" || in.Type == "" || in.Target == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name, type and target are required")
		return
	}
	trap, err := h.Store.CreateTrap(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create trap")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, trap)
}

func (h *Handlers) GetTrap(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	trap, err := h.Store.GetTrap(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, trap)
}

func (h *Handlers) UpdateTrap(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var patch models.TrapPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	trap, err := h.Store.UpdateTrap(r.Context(), id, patch)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update trap")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, trap)
}

func (h *Handlers) DeleteTrap(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.Store.DeleteTrap(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "trap not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete trap")
		return
	}
	w.WriteHeader(http.StatusNoContent) // 204 — script.js already handles this
}

func parseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
