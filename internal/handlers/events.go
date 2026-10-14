package handlers

// Обработчик HTTP запросов на события ловушек

import (
	"errors"
	"net/http"
	"strconv"

	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

// Обрабатывает GET запросы /api/traps/{id}/events.
func (h *Handlers) ListTrapEvents(w http.ResponseWriter, r *http.Request) {
	// Получаем числовое значение id ловушки из строки
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	f := models.EventFilter{TrapID: id, Limit: queryInt(r, "limit", 200)}
	events, err := h.Store.ListFilterEvents(r.Context(), f)
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

// Обрабатывает GET запросы /api/events с применением фильтров (FR-C4): trapId, type, src, since, limit.
func (h *Handlers) ListFilterEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Читаем параметры фильтров
	f := models.EventFilter{
		EventType: q.Get("type"),
		SrcIP:     q.Get("src"),
		Limit:     queryInt(r, "limit", 200),
	}
	if v := q.Get("trapId"); v != "" {
		if id, err := parseID(v); err == nil {
			f.TrapID = id
		}
	}
	if v := q.Get("since"); v != "" {
		if timeSince, err := strconv.ParseFloat(v, 64); err == nil {
			f.SinceTS = timeSince
		}
	}
	events, err := h.Store.ListFilterEvents(r.Context(), f)
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

// Возвращает целочисленное значение из запроса, при ошибке значение по умолчанию def
func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
