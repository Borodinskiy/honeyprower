package httpx

import (
	"encoding/json"
	"log"
	"net/http"
)

// MaxBodyBytes ограничивает размер JSON-тела запроса.
const MaxBodyBytes = 1 << 20 // 1 MiB

// WriteJSON writes v as JSON with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("httpx: encode: %v", err)
		}
	}
}

// WriteError emits {"error": "<msg>"} — matches the shape script.js expects.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// DecodeJSON читает тело запроса (не больше MaxBodyBytes) в v.
// При ошибке сам отвечает 400/413 и возвращает false.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			WriteError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		WriteError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}
