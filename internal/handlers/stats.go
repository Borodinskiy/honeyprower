package handlers

import (
	"net/http"
	"time"

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

// dashboardRanges — допустимые окна дашборда и размер ведра графика активности.
var dashboardRanges = map[string]struct{ window, bucket time.Duration }{
	"1h":  {time.Hour, 5 * time.Minute},
	"24h": {24 * time.Hour, time.Hour},
	"7d":  {7 * 24 * time.Hour, 6 * time.Hour},
}

// GetDashboard обрабатывает GET /api/stats/dashboard?range=1h|24h|7d&tz=<минуты к UTC>
// (по умолчанию 24h и UTC). tz — смещение местного времени зрителя, например 180 для UTC+3.
func (h *Handlers) GetDashboard(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("range")
	if name == "" {
		name = "24h"
	}
	rng, ok := dashboardRanges[name]
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "range must be 1h, 24h or 7d")
		return
	}
	tz := queryInt(r, "tz", 0)
	if tz < -14*60 || tz > 14*60 {
		httpx.WriteError(w, http.StatusBadRequest, "tz must be minutes from UTC")
		return
	}
	d, err := h.Store.GetDashboard(r.Context(), rng.window, rng.bucket, time.Duration(tz)*time.Minute)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load dashboard")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}
