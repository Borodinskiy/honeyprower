package handlers

// Обработчик HTTP запросов на получение ловушки

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

// Соответствует конфигурации нашей ловушки из config.rs.
// Конфигурация отправляется вместе со скомпиленным файлом.
// Никакие запросы в сервер на получение конифгурации от ловушки поступать не должны.
type agentTrap struct {
	Class  string          `json:"class"`
	Bind   string          `json:"bind"`
	Port   int             `json:"port"`
	Ports  string          `json:"ports,omitempty"`
	Name   string          `json:"name"`
	Params json.RawMessage `json:"params"`
}

// Конфигурация агента для отправки логов
type agentConfig struct {
	CenterURL     string    `json:"center_url"`
	Token         string    `json:"token"`
	ServerPubKey  string    `json:"server_pub_key,omitempty"`
	Transport     string    `json:"transport,omitempty"`
	StealthPaths  []string  `json:"stealth_paths,omitempty"`
	JitterS       int       `json:"jitter_s,omitempty"`
	VerifyTLS     bool      `json:"verify_tls"`
	RetryInterval int       `json:"retry_interval_s"`
	Trap          agentTrap `json:"trap"`
}

// Собрать конфигурационный файл развёртывания ловушки
func (h *Handlers) buildConfig(r *http.Request, t *models.Trap) agentConfig {
	params := t.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	return agentConfig{
		CenterURL:     h.centerURL(r),
		Token:         t.Token,
		ServerPubKey:  t.PubKey,
		Transport:     "http_nolinger",
		StealthPaths:  []string{"/cdn-cgi/rum", "/v1/rgstr", "/api/v2/metrics"},
		JitterS:       10,
		VerifyTLS:     true,
		RetryInterval: 10,
		Trap: agentTrap{
			Class:  t.Class,
			Bind:   t.Bind,
			Port:   t.Port,
			Ports:  t.Ports,
			Name:   t.Name,
			Params: params,
		},
	}
}

// Получить URL сервера, куда агент сохраняет логи.
// PublicURL в приоритете, иначе ссылка берётся из запроса, который просил конфигурацию
// TODO: разобраться с функционалом при хостинге с https.
func (h *Handlers) centerURL(r *http.Request) string {
	if h.PublicURL != "" {
		return strings.TrimRight(h.PublicURL, "/")
	}
	scheme := "http"
	// Определение вида соединения (http/https), если сервер спрятан за прокси (например, nginx)
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Host
	// Fallback на локальный хостинг (зачем? а я ебу)
	if host == "" {
		host = "127.0.0.1:8080"
	}
	return scheme + "://" + host
}

// Возвращает информацию об скачиваемой ловушке
func (h *Handlers) trapForDownload(w http.ResponseWriter, r *http.Request) (*models.Trap, bool) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return nil, false
	}
	trap, err := h.Store.GetTrap(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return nil, false
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap")
		return nil, false
	}
	return trap, true
}

// Отправляет конфиг ловушки.
func (h *Handlers) TrapConfig(w http.ResponseWriter, r *http.Request) {
	trap, ok := h.trapForDownload(w, r)
	if !ok {
		return
	}
	cfg := h.buildConfig(r, trap)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="config.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(cfg)
}

// Отправляет zip архив с конфигурацией ловушки и инструкциями запуска
func (h *Handlers) TrapBundle(w http.ResponseWriter, r *http.Request) {
	trap, ok := h.trapForDownload(w, r)
	if !ok {
		return
	}
	cfg := h.buildConfig(r, trap)
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if f, err := zw.Create("config.json"); err == nil {
		_, _ = f.Write(cfgBytes)
	}
	if f, err := zw.Create("RUN.txt"); err == nil {
		_, _ = f.Write([]byte(generateRunInstructions(trap, cfg)))
	}
	if err := zw.Close(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to build bundle")
		return
	}

	fname := fmt.Sprintf("honeyforge-trap-%d.zip", trap.ID)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	_, _ = w.Write(buf.Bytes())
}

// Возвращает строку с инструкциями по запуску
func generateRunInstructions(t *models.Trap, cfg agentConfig) string {
	where := fmt.Sprintf("%s:%d", t.Bind, t.Port)
	if t.Ports != "" {
		where = fmt.Sprintf("%s ports %s", t.Bind, t.Ports)
	}
	return fmt.Sprintf(`HoneyForge — ловушка «%s» (класс %s)

1. Соберите агент (однократно):
     cd agent && cargo build --release

2. Положите config.json из этого архива рядом с бинарником и запустите:
     ./honeyforge-agent config.json

Ловушка поднимется на %s и будет слать телеметрию в центр:
     %s/api/ingest

Токен ловушки уже вписан в config.json. Канал односторонний: из центра
к агенту ничего не идёт. Чтобы изменить ловушку — обновите её на сайте,
скачайте новый config.json и перезапустите агент.
`, t.Name, t.Class, where, cfg.CenterURL)
}
