package httpx

// Набор вспомогательных функций для работы с телом HTTP запроса, ответа, и немного JSONа

import (
	"encoding/json"
	"log"
	"net/http"
)

// Ограничивает размер JSON-тела запроса.
const MaxBodyBytes = 1 << 20 // 1 MiB

// Записывает ответ и код статуса в v как JSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("httpx: encode: %v", err)
		}
	}
}

// Оформляет ответ в стиле { "error": "<msg>" } - это соответствует обработке ошибок во фронтэнде (script.js)
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// Читает тело запроса (не больше MaxBodyBytes) в v.
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
