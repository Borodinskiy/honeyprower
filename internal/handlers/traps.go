package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

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
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Type = strings.TrimSpace(in.Type)
	in.Target = strings.TrimSpace(in.Target)
	if in.Name == "" || in.Type == "" || in.Target == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name, type and target are required")
		return
	}
	if msg := validateTrapFields(&in.Name, &in.Type, &in.Target); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
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
	if !httpx.DecodeJSON(w, r, &patch) {
		return
	}
	for _, f := range []*string{patch.Name, patch.Type, patch.Target} {
		if f == nil {
			continue
		}
		*f = strings.TrimSpace(*f)
		if *f == "" {
			httpx.WriteError(w, http.StatusBadRequest, "name, type and target must not be empty")
			return
		}
	}
	if msg := validateTrapFields(patch.Name, patch.Type, patch.Target); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
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

// Ограничения длины совпадают с размерами колонок в migrations/001_schema.sql.
const (
	maxTrapNameLen   = 255
	maxTrapTypeLen   = 50
	maxTrapTargetLen = 255
)

// validateTrapFields проверяет длину непустых полей; nil-поля пропускаются.
// Возвращает текст ошибки или "".
func validateTrapFields(name, typ, target *string) string {
	switch {
	case name != nil && utf8.RuneCountInString(*name) > maxTrapNameLen:
		return "name is too long"
	case typ != nil && utf8.RuneCountInString(*typ) > maxTrapTypeLen:
		return "type is too long"
	case target != nil && utf8.RuneCountInString(*target) > maxTrapTargetLen:
		return "target is too long"
	}
	return ""
}
