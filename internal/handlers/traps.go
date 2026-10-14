package handlers

import (
	"crypto/rand"
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
	if msg := validateTrap(&in); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
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
	if errors.Is(err, storage.ErrAlreadyExists) {
		httpx.WriteError(w, http.StatusConflict, "trap token collision, retry")
		return
	}
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
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" || utf8.RuneCountInString(name) > maxTrapNameLen {
			httpx.WriteError(w, http.StatusBadRequest, "invalid name")
			return
		}
		patch.Name = &name
	}
	if patch.Params != nil {
		// Схема параметров зависит от класса, поэтому сначала берём ловушку.
		cur, err := h.Store.GetTrap(r.Context(), id)
		if errors.Is(err, storage.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "trap not found")
			return
		}
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap")
			return
		}
		ports := ""
		if patch.Ports != nil {
			ports = *patch.Ports
		}
		params, msg := prepareParams(cur.Class, *patch.Params, &ports)
		if msg != "" {
			httpx.WriteError(w, http.StatusBadRequest, msg)
			return
		}
		patch.Params = &params
		if ports != "" {
			patch.Ports = &ports
		}
	}
	if patch.Port != nil && (*patch.Port < 0 || *patch.Port > 65535) {
		httpx.WriteError(w, http.StatusBadRequest, "port out of range")
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
	w.WriteHeader(http.StatusNoContent)
}

// Classes serves the trap-class catalog that drives the create form.
func (h *Handlers) Classes(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, catalog.Classes())
}

// Presets serves ready-made trap configurations.
func (h *Handlers) Presets(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, catalog.Presets())
}

func validateTrap(in *models.TrapCreate) string {
	if in.Name == "" {
		return "name is required"
	}
	if utf8.RuneCountInString(in.Name) > maxTrapNameLen {
		return "name is too long"
	}
	class, ok := catalog.ClassByID(in.Class)
	if !ok {
		return "unknown trap class"
	}
	params, msg := prepareParams(class.ID, in.Params, &in.Ports)
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
func prepareParams(classID string, params json.RawMessage, ports *string) (json.RawMessage, string) {
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
	if class, _ := catalog.ClassByID(classID); class.MultiPort {
		if p, ok := obj["ports"].(string); ok {
			if strings.TrimSpace(*ports) == "" {
				*ports = p
			}
			delete(obj, "ports")
		}
	}
	if err := catalog.ValidateParams(classID, obj); err != nil {
		return nil, "invalid params: " + err.Error()
	}
	if classID == "honeytoken" {
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

// fillHoneytokens gives every link without an ID a random one: the agent can
// only recognise a hit by a non-empty token.
func fillHoneytokens(obj map[string]any) error {
	tokens, _ := obj["tokens"].([]any)
	for _, it := range tokens {
		t, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if s, _ := t["token"].(string); strings.TrimSpace(s) == "" {
			b := make([]byte, 8)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			t["token"] = hex.EncodeToString(b)
		}
		if _, ok := t["kind"]; !ok {
			t["kind"] = "url"
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

func parseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
