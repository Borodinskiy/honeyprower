package handlers

// Свои ловушки: загрузка проекта пользователя и управление им (см. internal/plugin).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"honeyprower/internal/catalog"
	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/plugin"
	"honeyprower/internal/storage"
)

type pluginUse struct {
	TrapID int64  `json:"trapId"`
	Trap   string `json:"trap"`
	HostID *int64 `json:"hostId,omitempty"`
	Error  string `json:"error,omitempty"`
}

type pluginView struct {
	Name        string      `json:"name"`
	Class       string      `json:"class"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Version     string      `json:"version,omitempty"`
	Mode        string      `json:"mode"`
	Transport   string      `json:"transport"`
	Command     []string    `json:"command"`
	DefaultPort int         `json:"defaultPort,omitempty"`
	Requires    []string    `json:"requires"`
	Params      int         `json:"params"`
	SHA256      string      `json:"sha256"`
	Size        int64       `json:"size"`
	UploadedAt  time.Time   `json:"uploadedAt"`
	UsedBy      []pluginUse `json:"usedBy"`
}

func newPluginView(rec models.Plugin, m *plugin.Manifest, traps []models.Trap) pluginView {
	v := pluginView{
		Name: rec.Name, Class: m.ClassID(), Title: m.Title, Description: m.Description, Version: m.Version,
		Mode: m.Mode, Transport: m.Transport, Command: m.Command, DefaultPort: m.DefaultPort,
		Requires: m.Requires, Params: len(m.Params), SHA256: rec.SHA256, Size: rec.Size, UploadedAt: rec.UploadedAt,
		UsedBy: usesOf(m.ClassID(), traps),
	}
	if v.Requires == nil {
		v.Requires = []string{}
	}
	return v
}

func usesOf(classID string, traps []models.Trap) []pluginUse {
	out := []pluginUse{}
	for _, t := range traps {
		if t.Class == classID {
			out = append(out, pluginUse{TrapID: t.ID, Trap: t.Name, HostID: t.HostID})
		}
	}
	return out
}

// ListPlugins обрабатывает GET /api/plugins.
func (h *Handlers) ListPlugins(w http.ResponseWriter, r *http.Request) {
	cs, traps, ok := h.classesAndTraps(w, r)
	if !ok {
		return
	}
	out := []pluginView{}
	for _, c := range cs.list() {
		if p := cs.plugin(c.ID); p != nil {
			out = append(out, newPluginView(p.rec, p.manifest, traps))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// GetPlugin обрабатывает GET /api/plugins/{name}.
func (h *Handlers) GetPlugin(w http.ResponseWriter, r *http.Request) {
	cs, traps, ok := h.classesAndTraps(w, r)
	if !ok {
		return
	}
	p := cs.plugin(plugin.ClassPrefix + r.PathValue("name"))
	if p == nil {
		httpx.WriteError(w, http.StatusNotFound, "plugin not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newPluginView(p.rec, p.manifest, traps))
}

// UploadPlugin обрабатывает POST /api/plugins: архив проекта (zip или tar.gz) —
// в поле "archive" формы multipart или телом запроса. Плагин с тем же именем
// заменяется, если новая версия подходит к уже созданным на нём ловушкам.
func (h *Handlers) UploadPlugin(w http.ResponseWriter, r *http.Request) {
	data, msg := readUpload(w, r)
	if msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	bundle, err := plugin.Load(data)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid plugin: "+err.Error())
		return
	}
	m := bundle.Manifest

	cs, traps, ok := h.classesAndTraps(w, r)
	if !ok {
		return
	}
	prev := cs.plugin(m.ClassID())
	if prev != nil {
		if broken := checkPluginUpdate(cs, m, bundle.SHA256, traps); len(broken) > 0 {
			httpx.WriteJSON(w, http.StatusConflict, map[string]any{
				"error": "plugin update breaks traps",
				"traps": broken,
			})
			return
		}
	}

	rec, err := h.Store.SavePlugin(r.Context(), models.Plugin{
		Name: m.Name, Manifest: mustJSON(m), SHA256: bundle.SHA256,
	}, bundle.Archive)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save plugin")
		return
	}
	status := http.StatusCreated
	if prev != nil {
		status = http.StatusOK
	}
	httpx.WriteJSON(w, status, newPluginView(*rec, m, traps))
}

// checkPluginUpdate проверяет, что ловушки на этом плагине останутся рабочими
// с новой версией: параметры подходят к новой схеме, порты не столкнутся.
func checkPluginUpdate(cs *classSet, m *plugin.Manifest, sha string, traps []models.Trap) []pluginUse {
	next := *cs
	next.byID = make(map[string]catalog.Class, len(cs.byID))
	for k, v := range cs.byID {
		next.byID[k] = v
	}
	next.byID[m.ClassID()] = m.Class(sha)

	var broken []pluginUse
	for i := range traps {
		t := &traps[i]
		if t.Class != m.ClassID() {
			continue
		}
		ports := t.Ports
		if _, msg := prepareParams(next.byID[t.Class], t.Params, &ports); msg != "" {
			broken = append(broken, pluginUse{TrapID: t.ID, Trap: t.Name, HostID: t.HostID, Error: msg})
			continue
		}
		if socket, other := portClash(t, traps, &next); other != nil {
			broken = append(broken, pluginUse{TrapID: t.ID, Trap: t.Name, HostID: t.HostID,
				Error: fmt.Sprintf("port conflict %s with trap %q", socket, other.Name)})
		}
	}
	return broken
}

// DeletePlugin обрабатывает DELETE /api/plugins/{name}. Плагин, на котором
// есть ловушки, удалить нельзя: их нечем было бы запустить.
func (h *Handlers) DeletePlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	traps, err := h.Store.ListTraps(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load traps")
		return
	}
	if uses := usesOf(plugin.ClassPrefix+name, traps); len(uses) > 0 {
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{"error": "plugin is used by traps", "traps": uses})
		return
	}
	if err := h.Store.DeletePlugin(r.Context(), name); errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "plugin not found")
		return
	} else if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete plugin")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PluginArchive обрабатывает GET /api/plugins/{name}/archive: проект в том виде,
// в каком он уезжает на хосты.
func (h *Handlers) PluginArchive(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	archive, err := h.Store.GetPluginArchive(r.Context(), name)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "plugin not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load plugin")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".tar.gz"}))
	_, _ = w.Write(archive)
}

// PluginTemplate обрабатывает GET /api/plugin-templates/{kind}: стартовый проект.
func (h *Handlers) PluginTemplate(w http.ResponseWriter, r *http.Request) {
	name, data, err := plugin.Template(r.PathValue("kind"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "template not found")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"}))
	_, _ = w.Write(data)
}

func (h *Handlers) classesAndTraps(w http.ResponseWriter, r *http.Request) (*classSet, []models.Trap, bool) {
	cs, err := h.loadClasses(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap classes")
		return nil, nil, false
	}
	traps, err := h.Store.ListTraps(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load traps")
		return nil, nil, false
	}
	return cs, traps, true
}

// readUpload берёт архив из поля "archive" формы multipart или из тела запроса.
func readUpload(w http.ResponseWriter, r *http.Request) ([]byte, string) {
	r.Body = http.MaxBytesReader(w, r.Body, plugin.MaxArchiveBytes+1<<20)
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var src io.Reader = r.Body
	if ct == "multipart/form-data" {
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, "bad multipart form"
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return nil, "archive field is required"
			}
			if err != nil {
				return nil, uploadError(err)
			}
			if part.FormName() == "archive" {
				src = part
				break
			}
		}
	}
	data, err := io.ReadAll(io.LimitReader(src, plugin.MaxArchiveBytes+1))
	if err != nil {
		return nil, uploadError(err)
	}
	if len(data) == 0 {
		return nil, "archive is empty"
	}
	if len(data) > plugin.MaxArchiveBytes {
		return nil, fmt.Sprintf("archive is larger than %d MB", plugin.MaxArchiveBytes>>20)
	}
	return data, ""
}

func uploadError(err error) string {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) || strings.Contains(err.Error(), "too large") {
		return fmt.Sprintf("archive is larger than %d MB", plugin.MaxArchiveBytes>>20)
	}
	return "failed to read upload"
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
