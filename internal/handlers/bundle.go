package handlers

// Обработчик HTTP запросов на получение ловушки

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"

	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/plugin"
	"honeyprower/internal/storage"
)

// Соответствует конфигурации ловушки из agent/src/config.rs.
// Конфигурация отправляется вместе со скомпиленным файлом.
// Никакие запросы в сервер на получение конифгурации от ловушки поступать не должны.
type agentTrap struct {
	// Токен и ключ — только в конфиге хоста (traps): у каждой ловушки свои.
	Token        string          `json:"token,omitempty"`
	ServerPubKey string          `json:"server_pub_key,omitempty"`
	Class        string          `json:"class"`
	Bind         string          `json:"bind"`
	Port         int             `json:"port"`
	Ports        string          `json:"ports,omitempty"`
	Name         string          `json:"name"`
	Params       json.RawMessage `json:"params"`
	// Своя ловушка: класс у агента — "plugin", а здесь — что и откуда запускать.
	Plugin *agentPlugin `json:"plugin,omitempty"`
}

// agentPlugin соответствует PluginSpec из agent/src/config.rs.
type agentPlugin struct {
	Slug      string   `json:"slug"`
	Dir       string   `json:"dir"`
	Command   []string `json:"command"`
	Mode      string   `json:"mode"`
	Transport string   `json:"transport"`
}

// Конфигурация агента для отправки логов. Одна ловушка — Trap с токеном в
// корне (старый формат), хост — Traps, по ловушке на элемент.
type agentConfig struct {
	CenterURL     string      `json:"center_url"`
	Token         string      `json:"token,omitempty"`
	ServerPubKey  string      `json:"server_pub_key,omitempty"`
	Transport     string      `json:"transport,omitempty"`
	CenterUDP     string      `json:"center_udp,omitempty"`
	StealthPaths  []string    `json:"stealth_paths,omitempty"`
	JitterS       int         `json:"jitter_s,omitempty"`
	VerifyTLS     bool        `json:"verify_tls"`
	RetryInterval int         `json:"retry_interval_s"`
	Trap          *agentTrap  `json:"trap,omitempty"`
	Traps         []agentTrap `json:"traps,omitempty"`

	// Плагины, которые запускает этот конфиг: их архивы едут на хост вместе с агентом.
	plugins []*loadedPlugin
}

func (h *Handlers) baseConfig(r *http.Request) agentConfig {
	center := h.centerURL(r)
	transport, udp := "http_nolinger", ""
	if h.AgentTransport == "udp_burst" {
		transport, udp = "udp_burst", h.centerUDP(center)
	}
	return agentConfig{
		CenterURL:     center,
		Transport:     transport,
		CenterUDP:     udp,
		StealthPaths:  []string{"/cdn-cgi/rum", "/v1/rgstr", "/api/v2/metrics"},
		JitterS:       10,
		VerifyTLS:     true,
		RetryInterval: 10,
	}
}

// toAgentTrap переводит ловушку в формат агента. remote — конфиг для хоста,
// куда центр сам доставит плагины; иначе плагин ищется рядом с конфигом.
func (cfg *agentConfig) toAgentTrap(t *models.Trap, cs *classSet, remote bool) agentTrap {
	params := t.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	at := agentTrap{
		Class:  t.Class,
		Bind:   t.Bind,
		Port:   t.Port,
		Ports:  t.Ports,
		Name:   t.Name,
		Params: params,
	}
	if p := cs.plugin(t.Class); p != nil {
		at.Class = "plugin"
		at.Plugin = &agentPlugin{
			Slug:      p.rec.Name,
			Dir:       pluginDir(p, remote),
			Command:   p.manifest.Command,
			Mode:      p.manifest.Mode,
			Transport: p.manifest.Transport,
		}
		seen := false
		for _, q := range cfg.plugins {
			seen = seen || q == p
		}
		if !seen {
			cfg.plugins = append(cfg.plugins, p)
		}
	}
	return at
}

// Собрать конфигурационный файл развёртывания одной ловушки
func (h *Handlers) buildConfig(r *http.Request, t *models.Trap, cs *classSet, remote bool) agentConfig {
	cfg := h.baseConfig(r)
	cfg.Token = t.Token
	cfg.ServerPubKey = t.PubKey
	at := cfg.toAgentTrap(t, cs, remote)
	cfg.Trap = &at
	return cfg
}

// Собрать конфиг агента хоста: все переданные ловушки, у каждой свои токен и ключ.
func (h *Handlers) buildHostConfig(r *http.Request, traps []models.Trap, cs *classSet, remote bool) agentConfig {
	cfg := h.baseConfig(r)
	cfg.Traps = make([]agentTrap, 0, len(traps))
	for i := range traps {
		at := cfg.toAgentTrap(&traps[i], cs, remote)
		at.Token = traps[i].Token
		at.ServerPubKey = traps[i].PubKey
		cfg.Traps = append(cfg.Traps, at)
	}
	return cfg
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

// centerUDP — адрес UDP-приёмника для агентов: CenterUDP, где пустой хост
// заменяется хостом из адреса центра.
func (h *Handlers) centerUDP(center string) string {
	host, port, err := net.SplitHostPort(h.CenterUDP)
	if err != nil || port == "" {
		return h.CenterUDP
	}
	if host == "" {
		if u, err := url.Parse(center); err == nil {
			host = u.Hostname()
		}
	}
	return net.JoinHostPort(host, port)
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
	cs, err := h.loadClasses(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap classes")
		return
	}
	cfg := h.buildConfig(r, trap, cs, false)
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
	cs, err := h.loadClasses(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap classes")
		return
	}
	cfg := h.buildConfig(r, trap, cs, false)
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if f, err := zw.Create("config.json"); err == nil {
		_, _ = f.Write(cfgBytes)
	}
	// Своя ловушка: её файлы — рядом с конфигом, в том каталоге, где агент их ищет.
	for _, p := range cfg.plugins {
		archive, err := h.Store.GetPluginArchive(r.Context(), p.rec.Name)
		if err == nil {
			err = addPluginToZip(zw, pluginDir(p, false), archive)
		}
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to pack plugin")
			return
		}
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
	extra := ""
	for _, p := range cfg.plugins {
		extra += fmt.Sprintf("\nСвоя ловушка «%s»: её файлы лежат в %s — держите этот каталог рядом\nс config.json.", p.manifest.Title, pluginDir(p, false))
		if len(p.manifest.Requires) > 0 {
			extra += " На машине должны быть: " + strings.Join(p.manifest.Requires, ", ") + "."
		}
		if len(p.manifest.Pip) > 0 {
			extra += "\nЗависимости Python поставьте в каталог проекта (агент сам добавит его в PYTHONPATH):\n" +
				"     python3 -m pip install --target " + pluginDir(p, false) + "/.hf-pydeps " + shellQuote(p.manifest.Pip) + "\n"
		} else if len(p.manifest.PythonModules) > 0 {
			extra += " Модули Python: " + strings.Join(p.manifest.PythonModules, ", ") + "."
		}
		for _, mgr := range plugin.PackageManagers {
			if pkgs := p.manifest.Packages[mgr]; len(pkgs) > 0 {
				extra += "\nСистемные пакеты (" + mgr + "): " + strings.Join(pkgs, " ") + "."
			}
		}
		extra += "\n"
	}
	sink := cfg.CenterURL + " — зашифрованно, POST на " + strings.Join(cfg.StealthPaths, ", ")
	if cfg.Transport == "udp_burst" {
		sink = cfg.CenterUDP + " — зашифрованно, UDP-датаграммами"
	}
	return fmt.Sprintf(`HoneyForge — ловушка «%s» (класс %s)

1. Соберите агент (однократно):
     cd agent && cargo build --release

2. Распакуйте этот архив, положите бинарник рядом с config.json и запустите:
     ./honeyforge-agent config.json
%s
Ловушка поднимется на %s и будет слать телеметрию в центр:
     %s

Токен ловушки уже вписан в config.json. Канал односторонний: из центра
к агенту ничего не идёт. Чтобы изменить ловушку — обновите её на сайте,
скачайте новый config.json и перезапустите агент.
`, t.Name, t.Class, extra, where, sink)
}

// addPluginToZip раскладывает архив плагина в zip под каталогом dir, сохраняя
// биты исполнения (их видит unzip) и ссылки.
func addPluginToZip(zw *zip.Writer, dir string, archive []byte) error {
	return plugin.Files(archive, func(h *tar.Header, r io.Reader) error {
		name := path.Join(dir, h.Name)
		zh := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: h.ModTime}
		switch h.Typeflag {
		case tar.TypeDir:
			zh.Name = name + "/"
			zh.SetMode(fs.ModeDir | 0o755)
			_, err := zw.CreateHeader(zh)
			return err
		case tar.TypeSymlink:
			zh.SetMode(fs.ModeSymlink | 0o777)
			w, err := zw.CreateHeader(zh)
			if err == nil {
				_, err = w.Write([]byte(h.Linkname))
			}
			return err
		default:
			zh.SetMode(fs.FileMode(h.Mode) & 0o777)
			w, err := zw.CreateHeader(zh)
			if err == nil {
				_, err = io.Copy(w, r)
			}
			return err
		}
	})
}

// shellQuote — аргументы для команды в инструкции: зависимости вроде paramiko>=3.4 в кавычках.
func shellQuote(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = "'" + strings.ReplaceAll(a, "'", "'\\''") + "'"
	}
	return strings.Join(out, " ")
}
