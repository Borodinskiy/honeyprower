package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"honeyprower/internal/catalog"
	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

const (
	maxTrapNameLen = 255
	maxParamsBytes = 256 * 1024
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
	in.Class = strings.TrimSpace(in.Class)
	in.Bind = strings.TrimSpace(in.Bind)
	if in.Bind == "" {
		in.Bind = "0.0.0.0"
	}
	cs, err := h.loadClasses(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap classes")
		return
	}
	if msg := validateTrap(&in, cs); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	cand := models.Trap{HostID: in.HostID, Class: in.Class, Port: in.Port, Ports: in.Ports, Enabled: in.Enabled}
	if !h.checkTrapPlacement(w, r, &cand, cs) {
		return
	}

	token, err := genToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate trap crypto keys")
		return
	}
	in.KeyID = keyID
	in.PubKey = pubHex
	in.PrivKey = privHex
	trap, err := h.Store.CreateTrap(r.Context(), in, token)
	if errors.Is(err, storage.ErrNoSuchHost) {
		httpx.WriteError(w, http.StatusBadRequest, "host not found")
		return
	}
	if errors.Is(err, storage.ErrAlreadyExists) {
		httpx.WriteError(w, http.StatusConflict, "trap token collision, retry")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create trap")
		return
	}
	h.honeyCreds.reset()
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
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" || utf8.RuneCountInString(name) > maxTrapNameLen {
			httpx.WriteError(w, http.StatusBadRequest, "invalid name")
			return
		}
		patch.Name = &name
	}
	if patch.Port != nil && (*patch.Port < 0 || *patch.Port > 65535) {
		httpx.WriteError(w, http.StatusBadRequest, "port out of range")
		return
	}

	// Схема параметров зависит от класса, а проверка портов — от итогового вида ловушки.
	cur, err := h.Store.GetTrap(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap")
		return
	}
	cs, err := h.loadClasses(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap classes")
		return
	}
	if patch.Params != nil {
		class, ok := cs.class(cur.Class)
		if !ok {
			httpx.WriteError(w, http.StatusBadRequest, "unknown trap class")
			return
		}
		ports := ""
		if patch.Ports != nil {
			ports = *patch.Ports
		}
		params, msg := prepareParams(class, *patch.Params, &ports)
		if msg != "" {
			httpx.WriteError(w, http.StatusBadRequest, msg)
			return
		}
		patch.Params = &params
		if ports != "" {
			patch.Ports = &ports
		}
	}
	// Ловушка такой, какой станет после правки.
	next := *cur
	if patch.HostID.Set {
		next.HostID = patch.HostID.ID
	}
	if patch.Port != nil {
		next.Port = *patch.Port
	}
	if patch.Ports != nil {
		next.Ports = *patch.Ports
	}
	if patch.Enabled != nil {
		next.Enabled = *patch.Enabled
	}
	if !h.checkTrapPlacement(w, r, &next, cs) {
		return
	}

	trap, err := h.Store.UpdateTrap(r.Context(), id, patch)
	if errors.Is(err, storage.ErrNoSuchHost) {
		httpx.WriteError(w, http.StatusBadRequest, "host not found")
		return
	}
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update trap")
		return
	}
	h.honeyCreds.reset()
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
	h.honeyCreds.reset()
	w.WriteHeader(http.StatusNoContent)
}

// Classes serves the trap-class catalog that drives the create form:
// built-in classes and uploaded plugins.
func (h *Handlers) Classes(w http.ResponseWriter, r *http.Request) {
	cs, err := h.loadClasses(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap classes")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cs.list())
}

// Presets serves ready-made trap configurations.
func (h *Handlers) Presets(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, catalog.Presets())
}

// checkTrapPlacement проверяет, что хост ловушки существует и её порты на нём
// свободны. При ошибке сам отвечает клиенту и возвращает false.
func (h *Handlers) checkTrapPlacement(w http.ResponseWriter, r *http.Request, cand *models.Trap, cs *classSet) bool {
	if cand.HostID == nil {
		return true
	}
	if _, err := h.Store.GetHost(r.Context(), *cand.HostID); errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusBadRequest, "host not found")
		return false
	} else if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load host")
		return false
	}
	all, err := h.Store.ListTraps(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load traps")
		return false
	}
	if socket, other := portClash(cand, all, cs); other != nil {
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{
			"error":  "port conflict",
			"port":   socket,
			"trapId": other.ID,
			"trap":   other.Name,
		})
		return false
	}
	return true
}

func validateTrap(in *models.TrapCreate, cs *classSet) string {
	if in.Name == "" {
		return "name is required"
	}
	if utf8.RuneCountInString(in.Name) > maxTrapNameLen {
		return "name is too long"
	}
	class, ok := cs.class(in.Class)
	if !ok {
		return "unknown trap class"
	}
	params, msg := prepareParams(class, in.Params, &in.Ports)
	if msg != "" {
		return msg
	}
	in.Params = params
	if class.MultiPort {
		if strings.TrimSpace(in.Ports) == "" {
			return "ports are required for this class (e.g. 9000-9003)"
		}
	} else if in.Port < 1 || in.Port > 65535 {
		return "port must be 1..65535"
	}
	return ""
}

// prepareParams checks params against the class schema and fills values the
// center generates itself (honeytoken IDs). For multi-port classes a
// params.ports value moves into the trap's own ports field when that is empty.
// Returns normalized params or an error message.
func prepareParams(class catalog.Class, params json.RawMessage, ports *string) (json.RawMessage, string) {
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	if len(params) > maxParamsBytes {
		return nil, "params are too large"
	}
	var obj map[string]any
	if json.Unmarshal(params, &obj) != nil || obj == nil {
		return nil, "params must be a JSON object"
	}
	if class.MultiPort {
		if p, ok := obj["ports"].(string); ok {
			if strings.TrimSpace(*ports) == "" {
				*ports = p
			}
			delete(obj, "ports")
		}
	}
	if err := catalog.ValidateFields(class.Fields, obj); err != nil {
		return nil, "invalid params: " + err.Error()
	}
	if class.ID == "honeytoken" {
		if err := fillHoneytokens(obj); err != nil {
			return nil, "failed to generate token"
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, "params must be a JSON object"
	}
	return out, ""
}

// fillHoneytokens дополняет приманки тем, что генерирует центр: ID ссылки
// (агент узнаёт переход только по непустому ID) и пароль учётки.
func fillHoneytokens(obj map[string]any) error {
	tokens, _ := obj["tokens"].([]any)
	for _, it := range tokens {
		t, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if k, _ := t["kind"].(string); k == "" {
			t["kind"] = "url"
		}
		field, size := "token", 8
		if t["kind"] == "credentials" {
			field, size = "password", 9
		}
		if s, _ := t[field].(string); strings.TrimSpace(s) == "" {
			b := make([]byte, size)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			if field == "password" {
				t[field] = base64.RawURLEncoding.EncodeToString(b)
			} else {
				t[field] = hex.EncodeToString(b)
			}
		}
	}
	return nil
}

func genToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Возвращает идентификатор из строки
func parseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
