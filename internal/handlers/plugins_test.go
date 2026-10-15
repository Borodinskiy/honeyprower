package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"honeyprower/internal/catalog"
	"honeyprower/internal/deploy"
	"honeyprower/internal/models"
	"honeyprower/internal/plugin"
)

// pluginEnv — hostEnv с маршрутами своих ловушек и каталога классов.
func newPluginEnv(t *testing.T) *hostEnv {
	e := newHostEnv(t)
	e.mux.HandleFunc("GET /api/classes", e.h.Classes)
	e.mux.HandleFunc("GET /api/plugins", e.h.ListPlugins)
	e.mux.HandleFunc("POST /api/plugins", e.h.UploadPlugin)
	e.mux.HandleFunc("GET /api/plugins/{name}", e.h.GetPlugin)
	e.mux.HandleFunc("DELETE /api/plugins/{name}", e.h.DeletePlugin)
	e.mux.HandleFunc("GET /api/plugins/{name}/archive", e.h.PluginArchive)
	e.mux.HandleFunc("GET /api/plugin-templates/{kind}", e.h.PluginTemplate)
	e.mux.HandleFunc("GET /api/traps/{id}/bundle", e.h.TrapBundle)
	e.mux.HandleFunc("GET /api/traps/{id}/config", e.h.TrapConfig)
	return e
}

// ftpManifest — плагин с параметром-перечислением, чтобы проверять схему.
func ftpManifest(version string, levels ...string) string {
	if len(levels) == 0 {
		levels = []string{"low", "high"}
	}
	var opts []string
	for _, l := range levels {
		opts = append(opts, fmt.Sprintf(`{"value":%q,"label":%q}`, l, l))
	}
	return `{"name":"my-ftp","title":"Мой FTP","version":"` + version + `","mode":"service",
		"command":["./run.sh","--port-from-env"],"default_port":2121,"requires":["python3"],
		"params":[{"key":"banner","title":"Баннер","type":"string","default":"220 hi"},
		          {"key":"level","title":"Уровень","type":"enum","default":"` + levels[0] + `","options":[` + strings.Join(opts, ",") + `]}]}`
}

func pluginZip(t *testing.T, manifest string, extra ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{plugin.ManifestFile: manifest, "run.sh": "#!/bin/sh\nexec python3 server.py\n", "server.py": "print('hi')\n"}
	for i := 0; i+1 < len(extra); i += 2 {
		files[extra[i]] = extra[i+1]
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func (e *hostEnv) upload(data []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("archive", "plugin.zip")
	_, _ = fw.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/plugins", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *hostEnv) classes() map[string]catalog.Class {
	e.t.Helper()
	w := e.do("GET", "/api/classes", nil)
	e.expect(w, http.StatusOK)
	out := map[string]catalog.Class{}
	for _, c := range decodeInto[[]catalog.Class](e.t, w) {
		out[c.ID] = c
	}
	return out
}

func pluginTrap(host *int64, name string, port int, params map[string]any) map[string]any {
	b := map[string]any{"name": name, "class": "plugin:my-ftp", "port": port, "params": params, "enabled": true}
	if host != nil {
		b["hostId"] = *host
	}
	return b
}

func TestPluginUploadAndClasses(t *testing.T) {
	e := newPluginEnv(t)
	w := e.upload(pluginZip(t, ftpManifest("1.0")))
	e.expect(w, http.StatusCreated)
	v := decodeInto[pluginView](t, w)
	if v.Name != "my-ftp" || v.Class != "plugin:my-ftp" || v.Version != "1.0" || v.Mode != "service" ||
		len(v.SHA256) != 64 || v.Size == 0 || v.Params != 2 || len(v.UsedBy) != 0 || v.Requires[0] != "python3" {
		t.Fatalf("view = %+v", v)
	}

	c, ok := e.classes()["plugin:my-ftp"]
	if !ok {
		t.Fatal("плагин должен появиться в списке классов")
	}
	if c.Level != "Custom" || c.Origin != "plugin" || c.DefaultPort != 2121 || len(c.Fields) != 2 || c.SHA256 != v.SHA256 {
		t.Fatalf("class = %+v", c)
	}
	var defaults map[string]any
	_ = json.Unmarshal(c.DefaultParams, &defaults)
	if defaults["banner"] != "220 hi" || defaults["level"] != "low" {
		t.Fatalf("defaultParams = %v", defaults)
	}
	if _, ok := e.classes()["ssh"]; !ok {
		t.Fatal("встроенные классы остаются")
	}

	// тот же проект ещё раз — обновление, тот же хэш
	w = e.upload(pluginZip(t, ftpManifest("1.0")))
	e.expect(w, http.StatusOK)
	if decodeInto[pluginView](t, w).SHA256 != v.SHA256 {
		t.Fatal("одинаковый проект — одинаковый хэш")
	}

	// tar.gz телом запроса тоже принимается
	stored, _ := e.mem.GetPluginArchive(context.Background(), "my-ftp")
	req := httptest.NewRequest("POST", "/api/plugins", bytes.NewReader(stored))
	req.Header.Set("Content-Type", "application/gzip")
	rw := httptest.NewRecorder()
	e.mux.ServeHTTP(rw, req)
	e.expect(rw, http.StatusOK)

	list := decodeInto[[]pluginView](t, e.do("GET", "/api/plugins", nil))
	if len(list) != 1 || list[0].Name != "my-ftp" {
		t.Fatalf("list = %+v", list)
	}
	e.expect(e.do("GET", "/api/plugins/my-ftp", nil), http.StatusOK)
	e.expect(e.do("GET", "/api/plugins/nope", nil), http.StatusNotFound)
}

func TestPluginUploadRejectsBadInput(t *testing.T) {
	e := newPluginEnv(t)
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"не архив", []byte("hello"), "invalid plugin: нужен архив"},
		{"нет манифеста", func() []byte {
			var b bytes.Buffer
			zw := zip.NewWriter(&b)
			w, _ := zw.Create("server.py")
			_, _ = w.Write([]byte("x"))
			_ = zw.Close()
			return b.Bytes()
		}(), "нет " + plugin.ManifestFile},
		{"обход каталога", pluginZip(t, ftpManifest("1"), "../evil", "x"), "выходит за пределы"},
		{"плохое имя", pluginZip(t, strings.Replace(ftpManifest("1"), `"my-ftp"`, `"My FTP"`, 1)), "name"},
		{"чуть больше лимита", append([]byte("PK\x03\x04"), make([]byte, plugin.MaxArchiveBytes+10)...), "larger than 32 MB"},
		{"намного больше лимита", append([]byte("PK\x03\x04"), make([]byte, plugin.MaxArchiveBytes+4<<20)...), "larger than 32 MB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := e.upload(c.data)
			e.expect(w, http.StatusBadRequest)
			if msg := errorOf(t, w); !strings.Contains(msg, c.want) {
				t.Fatalf("error = %q, want %q", msg, c.want)
			}
		})
	}
	// пустая форма
	req := httptest.NewRequest("POST", "/api/plugins", strings.NewReader(""))
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	e.expect(w, http.StatusBadRequest)
	if list := decodeInto[[]pluginView](t, e.do("GET", "/api/plugins", nil)); len(list) != 0 {
		t.Fatal("плохие загрузки не должны сохраняться")
	}
}

func TestPluginTrapLifecycleOnHost(t *testing.T) {
	e := newPluginEnv(t)
	e.expect(e.upload(pluginZip(t, ftpManifest("1.0"))), http.StatusCreated)
	host := e.createHost(passwordHost("web", "10.0.0.5"))

	// параметры проверяются по схеме плагина
	w := e.do("POST", "/api/traps", pluginTrap(&host.ID, "ftp", 2121, map[string]any{"level": "ultra"}))
	e.expect(w, http.StatusBadRequest)
	if msg := errorOf(t, w); !strings.Contains(msg, "invalid params: level") {
		t.Fatalf("error = %q", msg)
	}
	ftp := e.createTrap(pluginTrap(&host.ID, "ftp", 2121, map[string]any{"level": "high", "banner": "220 Welcome"}))
	ssh := e.createTrap(sshTrap(host.ID, "ssh", 2222))

	// порт плагина участвует в проверке пересечений
	w = e.do("POST", "/api/traps", sshTrap(host.ID, "ssh2", 2121))
	e.expect(w, http.StatusConflict)

	// деплой: архив плагина едет вместе с агентом, в конфиге — как его запускать
	e.expect(e.do("POST", fmt.Sprintf("/api/hosts/%d/deploy", host.ID), nil), http.StatusOK)
	p := e.dep.lastPayload
	stored, _ := e.mem.GetPluginArchive(context.Background(), "my-ftp")
	rec, _ := e.mem.GetPlugin(context.Background(), "my-ftp")
	wantDir := "/opt/honeyforge/plugins/my-ftp-" + rec.SHA256[:12]
	if len(p.Plugins) != 1 || p.Plugins[0].Dir != wantDir || !bytes.Equal(p.Plugins[0].Archive, stored) ||
		p.Plugins[0].Requires[0] != "python3" {
		t.Fatalf("payload plugins = %+v", p.Plugins)
	}
	var cfg agentConfig
	if err := json.Unmarshal(p.ConfigJSON, &cfg); err != nil {
		t.Fatal(err)
	}
	var got map[int]agentTrap = map[int]agentTrap{}
	for _, at := range cfg.Traps {
		got[at.Port] = at
	}
	fa, sa := got[2121], got[2222]
	if fa.Class != "plugin" || fa.Plugin == nil || fa.Plugin.Slug != "my-ftp" || fa.Plugin.Dir != wantDir ||
		fa.Plugin.Mode != "service" || fa.Plugin.Transport != "tcp" || strings.Join(fa.Plugin.Command, " ") != "./run.sh --port-from-env" {
		t.Fatalf("ловушка-плагин в конфиге агента: %+v %+v", fa, fa.Plugin)
	}
	var params map[string]any
	_ = json.Unmarshal(fa.Params, &params)
	if params["banner"] != "220 Welcome" || params["level"] != "high" {
		t.Fatalf("params = %v", params)
	}
	if sa.Class != "ssh" || sa.Plugin != nil {
		t.Fatalf("встроенная ловушка не должна меняться: %+v", sa)
	}
	if e.getHost(host.ID).PendingChanges {
		t.Fatal("сразу после деплоя изменений нет")
	}

	// новая версия плагина помечает хост к обновлению
	e.expect(e.upload(pluginZip(t, ftpManifest("1.1"))), http.StatusOK)
	if !e.getHost(host.ID).PendingChanges {
		t.Fatal("новая загрузка плагина должна требовать обновить хост")
	}
	e.expect(e.do("POST", fmt.Sprintf("/api/hosts/%d/deploy", host.ID), nil), http.StatusOK)
	if dir := e.dep.lastPayload.Plugins[0].Dir; dir == wantDir {
		t.Fatal("новая версия — новый каталог на хосте")
	}

	// версия, несовместимая с параметрами ловушки, не принимается
	w = e.upload(pluginZip(t, ftpManifest("2.0", "low")))
	e.expect(w, http.StatusConflict)
	conflict := decodeInto[struct {
		Error string      `json:"error"`
		Traps []pluginUse `json:"traps"`
	}](t, w)
	if conflict.Error != "plugin update breaks traps" || len(conflict.Traps) != 1 || conflict.Traps[0].TrapID != ftp.ID ||
		!strings.Contains(conflict.Traps[0].Error, "level") {
		t.Fatalf("conflict = %+v", conflict)
	}
	if v := decodeInto[pluginView](t, e.do("GET", "/api/plugins/my-ftp", nil)); v.Version != "1.1" {
		t.Fatal("отклонённая версия не должна заменять текущую")
	}

	// удалить плагин с ловушками нельзя
	w = e.do("DELETE", "/api/plugins/my-ftp", nil)
	e.expect(w, http.StatusConflict)
	if uses := decodeInto[pluginView](t, e.do("GET", "/api/plugins/my-ftp", nil)).UsedBy; len(uses) != 1 || uses[0].TrapID != ftp.ID {
		t.Fatalf("usedBy = %+v", uses)
	}
	e.expect(e.do("DELETE", fmt.Sprintf("/api/traps/%d", ftp.ID), nil), http.StatusNoContent)
	e.expect(e.do("DELETE", "/api/plugins/my-ftp", nil), http.StatusNoContent)
	e.expect(e.do("DELETE", "/api/plugins/my-ftp", nil), http.StatusNotFound)
	if _, ok := e.classes()["plugin:my-ftp"]; ok {
		t.Fatal("удалённый плагин не должен оставаться в классах")
	}
	// без плагинов деплой не везёт ничего лишнего
	e.expect(e.do("POST", fmt.Sprintf("/api/hosts/%d/deploy", host.ID), nil), http.StatusOK)
	if len(e.dep.lastPayload.Plugins) != 0 {
		t.Fatal("плагинов на хосте больше нет")
	}
	_ = ssh
}

func TestPluginTransportAffectsPortConflicts(t *testing.T) {
	e := newPluginEnv(t)
	udp := `{"name":"dns-x","mode":"service","transport":"udp","command":["python3","dns.py"],"default_port":53}`
	e.expect(e.upload(pluginZip(t, udp)), http.StatusCreated)
	host := e.createHost(passwordHost("h", "10.0.0.9"))
	e.createTrap(map[string]any{"hostId": host.ID, "name": "dns", "class": "plugin:dns-x", "port": 2222, "params": map[string]any{}, "enabled": true})
	// тот же номер, но tcp — пересечения нет
	e.createTrap(sshTrap(host.ID, "ssh", 2222))
	w := e.do("POST", "/api/traps", map[string]any{"hostId": host.ID, "name": "dns2", "class": "plugin:dns-x", "port": 2222, "params": map[string]any{}, "enabled": true})
	e.expect(w, http.StatusConflict)
}

func TestPluginLooseTrapBundleAndConfig(t *testing.T) {
	e := newPluginEnv(t)
	e.expect(e.upload(pluginZip(t, ftpManifest("1.0"), "lib/helper.py", "x=1\n")), http.StatusCreated)
	rec, _ := e.mem.GetPlugin(context.Background(), "my-ftp")
	dir := "plugins/my-ftp-" + rec.SHA256[:12]
	trap := e.createTrap(pluginTrap(nil, "loose ftp", 2121, map[string]any{}))

	w := e.do("GET", fmt.Sprintf("/api/traps/%d/config", trap.ID), nil)
	e.expect(w, http.StatusOK)
	cfg := decodeInto[agentConfig](t, w)
	if cfg.Trap == nil || cfg.Trap.Plugin == nil || cfg.Trap.Plugin.Dir != dir {
		t.Fatalf("для ручного запуска плагин ищется рядом с конфигом: %+v", cfg.Trap)
	}

	w = e.do("GET", fmt.Sprintf("/api/traps/%d/bundle", trap.ID), nil)
	e.expect(w, http.StatusOK)
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	for _, name := range []string{"config.json", "RUN.txt", dir + "/" + plugin.ManifestFile, dir + "/run.sh", dir + "/lib/helper.py"} {
		if files[name] == nil {
			t.Fatalf("в пакете нет %s: %v", name, keysOf(files))
		}
	}
	if files[dir+"/run.sh"].Mode()&0o111 == 0 {
		t.Fatal("файл команды должен остаться исполняемым после распаковки")
	}
	if files[dir+"/lib/"] == nil || !files[dir+"/lib/"].Mode().IsDir() {
		t.Fatal("каталоги должны быть в zip")
	}
	rc, _ := files["RUN.txt"].Open()
	run, _ := io.ReadAll(rc)
	if !strings.Contains(string(run), dir) || !strings.Contains(string(run), "python3") {
		t.Fatalf("RUN.txt должен рассказать про плагин: %s", run)
	}

	// хост-конфиг для ручного запуска — тоже с относительным путём
	host := e.createHost(passwordHost("h", "10.0.0.7"))
	e.createTrap(pluginTrap(&host.ID, "ftp", 2121, map[string]any{}))
	hc := decodeInto[agentConfig](t, e.do("GET", fmt.Sprintf("/api/hosts/%d/config", host.ID), nil))
	if hc.Traps[0].Plugin == nil || hc.Traps[0].Plugin.Dir != dir {
		t.Fatalf("host config = %+v", hc.Traps[0])
	}
}

func keysOf(m map[string]*zip.File) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPluginArchiveAndTemplates(t *testing.T) {
	e := newPluginEnv(t)
	e.expect(e.upload(pluginZip(t, ftpManifest("1.0"))), http.StatusCreated)
	w := e.do("GET", "/api/plugins/my-ftp/archive", nil)
	e.expect(w, http.StatusOK)
	stored, _ := e.mem.GetPluginArchive(context.Background(), "my-ftp")
	if !bytes.Equal(w.Body.Bytes(), stored) || !strings.Contains(w.Header().Get("Content-Disposition"), "my-ftp.tar.gz") {
		t.Fatal("скачивается ровно то, что уезжает на хосты")
	}
	e.expect(e.do("GET", "/api/plugins/nope/archive", nil), http.StatusNotFound)

	for _, kind := range plugin.TemplateKinds {
		w := e.do("GET", "/api/plugin-templates/"+kind, nil)
		e.expect(w, http.StatusOK)
		// шаблон загружается обратно без правок
		up := e.upload(w.Body.Bytes())
		e.expect(up, http.StatusCreated)
	}
	e.expect(e.do("GET", "/api/plugin-templates/nope", nil), http.StatusNotFound)
	if n := len(decodeInto[[]pluginView](t, e.do("GET", "/api/plugins", nil))); n != 3 {
		t.Fatalf("плагинов %d, ждём 3", n)
	}
}

func TestBrokenStoredPluginDoesNotBreakClasses(t *testing.T) {
	e := newPluginEnv(t)
	_, _ = e.mem.SavePlugin(context.Background(), models.Plugin{Name: "broken", Manifest: json.RawMessage(`{"name":"broken"}`), SHA256: "x"}, []byte("x"))
	classes := e.classes()
	if _, ok := classes["plugin:broken"]; ok {
		t.Fatal("плагин с испорченным манифестом пропускается")
	}
	if _, ok := classes["ssh"]; !ok {
		t.Fatal("остальные классы на месте")
	}
	e.expect(e.do("GET", "/api/hosts", nil), http.StatusOK)
}

func TestTrapsHashOfBuiltinTrapsDoesNotDependOnPlugins(t *testing.T) {
	// Уже развёрнутые хосты не должны внезапно стать «требующими обновления» после
	// появления своих ловушек: отпечаток встроенных классов прежний.
	e := newPluginEnv(t)
	e.expect(e.upload(pluginZip(t, ftpManifest("1.0"))), http.StatusCreated)
	cs, err := e.h.loadClasses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	traps := []models.Trap{{ID: 1, Token: "t", Class: "ssh", Port: 22, Params: json.RawMessage(`{}`)}}
	if trapsHash(traps, cs) != trapsHash(traps, nil) {
		t.Fatal("отпечаток встроенных ловушек изменился")
	}
	withPlugin := []models.Trap{{ID: 2, Token: "u", Class: "plugin:my-ftp", Port: 21, Params: json.RawMessage(`{}`)}}
	if trapsHash(withPlugin, cs) == trapsHash(withPlugin, nil) {
		t.Fatal("версия плагина должна входить в отпечаток")
	}
}

func TestDeployPluginErrorReachesUser(t *testing.T) {
	e := newPluginEnv(t)
	e.expect(e.upload(pluginZip(t, ftpManifest("1.0"))), http.StatusCreated)
	host := e.createHost(passwordHost("h", "10.0.0.8"))
	e.createTrap(pluginTrap(&host.ID, "ftp", 2121, map[string]any{}))
	e.dep.deployFunc = func(ctx context.Context, target deploy.TargetConfig, payload deploy.Payload) error {
		return fmt.Errorf("%w: python3", deploy.ErrPluginRequirements)
	}
	w := e.do("POST", fmt.Sprintf("/api/hosts/%d/deploy", host.ID), nil)
	e.expect(w, http.StatusBadGateway)
	if msg := errorOf(t, w); msg != "plugin requirements not met on host: python3" {
		t.Fatalf("error = %q", msg)
	}
	if e.getHost(host.ID).DeployedAt != nil {
		t.Fatal("неудачный деплой не отмечается")
	}
}

var _ = fs.ModeDir

func TestHostStatusSeesPortOfServicePlugin(t *testing.T) {
	e := newPluginEnv(t)
	e.expect(e.upload(pluginZip(t, ftpManifest("1.0"))), http.StatusCreated)
	stdio := `{"name":"shell","mode":"stdio","command":["./run.sh"],"default_port":2424}`
	e.expect(e.upload(pluginZip(t, stdio)), http.StatusCreated)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	e.createTrap(pluginTrap(&host.ID, "ftp", 2121, map[string]any{}))
	e.createTrap(map[string]any{"hostId": host.ID, "name": "sh", "class": "plugin:shell", "port": 2424, "params": map[string]any{}, "enabled": true})
	e.createTrap(sshTrap(host.ID, "ssh", 2222))

	// 2121 держит python3 (программа плагина), 2424 и 2222 — агент
	e.dep.statusFunc = func(context.Context, deploy.TargetConfig) (*deploy.ServiceStatus, error) {
		return &deploy.ServiceStatus{Active: true, SubState: "active", Listening: []int{2222, 2424}, ListeningAll: []int{22, 2121, 2222, 2424}}, nil
	}
	st := decodeInto[hostStatusResponse](t, e.do("GET", fmt.Sprintf("/api/hosts/%d/status", host.ID), nil))
	if len(st.MissingPorts) != 0 {
		t.Fatalf("порт программы плагина не должен считаться пропавшим: %v", st.MissingPorts)
	}
	// stdio-плагин слушает сам агент: чужой процесс на этом порту не в счёт
	e.dep.statusFunc = func(context.Context, deploy.TargetConfig) (*deploy.ServiceStatus, error) {
		return &deploy.ServiceStatus{Active: true, SubState: "active", Listening: []int{2222}, ListeningAll: []int{2121, 2222, 2424}}, nil
	}
	st = decodeInto[hostStatusResponse](t, e.do("GET", fmt.Sprintf("/api/hosts/%d/status", host.ID), nil))
	if strings.Join(st.MissingPorts, ",") != "2424/tcp" {
		t.Fatalf("missing = %v", st.MissingPorts)
	}
}
