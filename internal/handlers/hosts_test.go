package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"honeyprower/internal/deploy"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

// hostsMux регистрирует маршруты хостов и ловушек с теми же шаблонами, что и
// router.NewAPI (без авторизации): так PathValue работает как в бою.
func hostsMux(h *Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/hosts", h.ListHosts)
	mux.HandleFunc("POST /api/hosts", h.CreateHost)
	mux.HandleFunc("GET /api/hosts/{id}", h.GetHost)
	mux.HandleFunc("PATCH /api/hosts/{id}", h.UpdateHost)
	mux.HandleFunc("DELETE /api/hosts/{id}", h.DeleteHost)
	mux.HandleFunc("GET /api/hosts/{id}/config", h.HostConfig)
	mux.HandleFunc("GET /api/hosts/{id}/status", h.HostStatus)
	mux.HandleFunc("POST /api/hosts/{id}/deploy", h.DeployHost)
	mux.HandleFunc("POST /api/hosts/{id}/undeploy", h.UndeployHost)
	mux.HandleFunc("GET /api/traps", h.ListTraps)
	mux.HandleFunc("POST /api/traps", h.CreateTrap)
	mux.HandleFunc("PATCH /api/traps/{id}", h.UpdateTrap)
	mux.HandleFunc("DELETE /api/traps/{id}", h.DeleteTrap)
	mux.HandleFunc("POST /api/traps/{id}/deploy", h.HandleDeployTrap)
	return mux
}

type hostEnv struct {
	t   *testing.T
	h   *Handlers
	mem *storage.Memory
	dep *mockDeployer
	mux *http.ServeMux
}

func newHostEnv(t *testing.T) *hostEnv {
	t.Helper()
	h, _, mem := setupTestHandlers()
	dep := &mockDeployer{}
	h.Deployer = dep

	// Деплой читает бинарник агента и unit-файл с диска.
	dir := t.TempDir()
	bin := filepath.Join(dir, "honeyforge-agent")
	svc := filepath.Join(dir, "honeyforge-agent.service")
	if err := os.WriteFile(bin, []byte("\x7fELF-fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HF_AGENT_BIN", bin)
	t.Setenv("HF_AGENT_SERVICE", svc)
	return &hostEnv{t: t, h: h, mem: mem, dep: dep, mux: hostsMux(h)}
}

func (e *hostEnv) do(method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = "center.example:8080"
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *hostEnv) expect(w *httptest.ResponseRecorder, code int) {
	e.t.Helper()
	if w.Code != code {
		e.t.Fatalf("status %d, want %d: %s", w.Code, code, w.Body.String())
	}
}

func decodeInto[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return v
}

func errorOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	return decodeInto[map[string]any](t, w)["error"].(string)
}

func (e *hostEnv) createHost(body map[string]any) models.Host {
	e.t.Helper()
	w := e.do("POST", "/api/hosts", body)
	e.expect(w, http.StatusCreated)
	return decodeInto[models.Host](e.t, w)
}

func (e *hostEnv) createTrap(body map[string]any) models.Trap {
	e.t.Helper()
	w := e.do("POST", "/api/traps", body)
	e.expect(w, http.StatusCreated)
	return decodeInto[models.Trap](e.t, w)
}

func (e *hostEnv) getHost(id int64) models.Host {
	e.t.Helper()
	w := e.do("GET", fmt.Sprintf("/api/hosts/%d", id), nil)
	e.expect(w, http.StatusOK)
	return decodeInto[models.Host](e.t, w)
}

func passwordHost(name, addr string) map[string]any {
	return map[string]any{"name": name, "address": addr, "sshPort": 22, "username": "deployer",
		"authType": "password", "password": "ssh-Pa55!" + name, "useSudo": true, "sudoPassword": "sudo-Pa55!" + name}
}

func sshTrap(host int64, name string, port int) map[string]any {
	return map[string]any{"hostId": host, "name": name, "class": "ssh", "port": port, "params": map[string]any{}, "enabled": true}
}

// looseTrap — ловушка без хоста (поле hostId не передаётся).
func looseTrap(name string, port int) map[string]any {
	return map[string]any{"name": name, "class": "ssh", "port": port, "params": map[string]any{}, "enabled": true}
}

func genKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

// ---------------------------------------------------------------------------

func TestHostCRUDNeverLeaksSecrets(t *testing.T) {
	e := newHostEnv(t)
	created := e.createHost(passwordHost("web", "10.0.0.5"))
	if !created.HasPassword || !created.HasSudoPassword || created.HasPrivateKey || created.SSHPort != 22 {
		t.Fatalf("unexpected host view: %+v", created)
	}

	// Ни один ответ не содержит паролей — ни открытых, ни зашифрованных.
	for _, w := range []*httptest.ResponseRecorder{
		e.do("GET", "/api/hosts", nil),
		e.do("GET", fmt.Sprintf("/api/hosts/%d", created.ID), nil),
	} {
		e.expect(w, http.StatusOK)
		body := w.Body.String()
		for _, leak := range []string{"ssh-Pa55!", "sudo-Pa55!", "v1:", "Enc"} {
			if strings.Contains(body, leak) {
				t.Fatalf("response leaks %q: %s", leak, body)
			}
		}
	}

	// В хранилище — шифротекст, который расшифровывается ключом центра.
	stored, _ := e.mem.GetHost(context.Background(), created.ID)
	if strings.Contains(stored.PasswordEnc, "ssh-Pa55!") {
		t.Fatal("password stored in plaintext")
	}
	if p, err := e.h.Secrets.Open(stored.PasswordEnc); err != nil || p != "ssh-Pa55!web" {
		t.Fatalf("stored password does not decrypt: %q, %v", p, err)
	}

	// PATCH без секретов (или с пустыми) их не трогает.
	w := e.do("PATCH", fmt.Sprintf("/api/hosts/%d", created.ID), map[string]any{"name": "web-renamed", "password": ""})
	e.expect(w, http.StatusOK)
	after, _ := e.mem.GetHost(context.Background(), created.ID)
	if after.Name != "web-renamed" || after.PasswordEnc != stored.PasswordEnc || after.SudoPasswordEnc != stored.SudoPasswordEnc {
		t.Fatalf("secrets changed by unrelated patch: %+v", after)
	}

	// Новый пароль заменяет старый.
	e.expect(e.do("PATCH", fmt.Sprintf("/api/hosts/%d", created.ID), map[string]any{"password": "new-one"}), http.StatusOK)
	after, _ = e.mem.GetHost(context.Background(), created.ID)
	if p, _ := e.h.Secrets.Open(after.PasswordEnc); p != "new-one" {
		t.Fatalf("password not replaced: %q", p)
	}

	e.expect(e.do("GET", "/api/hosts/999", nil), http.StatusNotFound)
	e.expect(e.do("GET", "/api/hosts/abc", nil), http.StatusBadRequest)
	e.expect(e.do("PATCH", "/api/hosts/999", map[string]any{"name": "x"}), http.StatusNotFound)
}

func TestHostValidation(t *testing.T) {
	e := newHostEnv(t)
	base := func(over map[string]any) map[string]any {
		b := map[string]any{"name": "h", "address": "10.9.9.9", "username": "root", "password": "pw"}
		for k, v := range over {
			b[k] = v
		}
		return b
	}
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"no name", base(map[string]any{"name": "  "}), "name is required"},
		{"long name", base(map[string]any{"name": strings.Repeat("я", 256)}), "name is too long"},
		{"no address", base(map[string]any{"address": ""}), "address is required"},
		{"address with space", base(map[string]any{"address": "10.0.0.1 x"}), "invalid address"},
		{"url as address", base(map[string]any{"address": "http://10.0.0.1"}), "invalid address"},
		{"leading dash", base(map[string]any{"address": "-bad.example"}), "invalid address"},
		{"port zero", base(map[string]any{"sshPort": 0}), "ssh port must be 1..65535"},
		{"port too big", base(map[string]any{"sshPort": 70000}), "ssh port must be 1..65535"},
		{"no username", base(map[string]any{"username": ""}), "username is required"},
		{"username with space", base(map[string]any{"username": "ro ot"}), "invalid username"},
		{"bad auth type", base(map[string]any{"authType": "token"}), "auth type must be password or key"},
		{"password auth without password", base(map[string]any{"password": ""}), "password is required"},
		{"key auth without key", base(map[string]any{"authType": "key", "password": ""}), "private key is required"},
		{"garbage key", base(map[string]any{"authType": "key", "privateKey": "not a key"}), "invalid private key"},
		{"encrypted key", base(map[string]any{"authType": "key", "privateKey": genKey(t, "pass")}), "encrypted private keys are not supported"},
		{"huge secret", base(map[string]any{"password": strings.Repeat("x", maxSecretLen+1)}), "secret is too long"},
	}
	for _, c := range cases {
		w := e.do("POST", "/api/hosts", c.body)
		if w.Code != http.StatusBadRequest || errorOf(t, w) != c.want {
			t.Errorf("%s: got %d %s, want 400 %q", c.name, w.Code, w.Body.String(), c.want)
		}
	}
	e.expect(e.do("POST", "/api/hosts", "{not json"), http.StatusBadRequest)

	// Допустимые адреса: IPv4, IPv6, DNS-имя.
	for i, addr := range []string{"192.168.0.10", "fe80::1", "honeypot-01.corp.example"} {
		e.createHost(base(map[string]any{"name": fmt.Sprint("ok", i), "address": addr}))
	}
	// Ключ без пароля принимается, по умолчанию порт 22 и пользователь root.
	k := e.createHost(map[string]any{"name": "keyed", "address": "10.1.1.1", "authType": "key", "privateKey": genKey(t, "")})
	if !k.HasPrivateKey || k.HasPassword || k.SSHPort != 22 || k.Username != "root" {
		t.Fatalf("defaults: %+v", k)
	}

	// Тот же сервер второй раз — конфликт (регистр адреса не важен).
	w := e.do("POST", "/api/hosts", base(map[string]any{"name": "dup", "address": "HONEYPOT-01.corp.example"}))
	if w.Code != http.StatusConflict || errorOf(t, w) != "host with this address already exists" {
		t.Fatalf("duplicate: %d %s", w.Code, w.Body.String())
	}
	w = e.do("PATCH", fmt.Sprintf("/api/hosts/%d", k.ID), map[string]any{"address": "192.168.0.10"})
	if w.Code != http.StatusConflict {
		t.Fatalf("patch onto taken address: %d %s", w.Code, w.Body.String())
	}
}

func TestHostSwitchAuthTypeUsesMatchingSecret(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	id := fmt.Sprintf("/api/hosts/%d", host.ID)

	// Переключиться на ключ без ключа нельзя.
	w := e.do("PATCH", id, map[string]any{"authType": "key"})
	if w.Code != http.StatusBadRequest || errorOf(t, w) != "private key is required" {
		t.Fatalf("switch without key: %d %s", w.Code, w.Body.String())
	}
	key := genKey(t, "")
	e.expect(e.do("PATCH", id, map[string]any{"authType": "key", "privateKey": key}), http.StatusOK)

	e.createTrap(sshTrap(host.ID, "ssh", 2222))
	e.expect(e.do("POST", id+"/deploy", nil), http.StatusOK)
	got := e.dep.lastTarget
	if got.PrivateKey != strings.TrimSpace(key)+"\n" || got.Password != "" {
		t.Fatalf("key auth must send only the key: %+v", got)
	}
	if got.RootPassword != "sudo-Pa55!web" || !got.UseSudo || got.Username != "deployer" || got.Host != "10.0.0.5" || got.Port != 22 {
		t.Fatalf("target: %+v", got)
	}

	// Обратно на пароль: сохранённый пароль снова в ходу.
	e.expect(e.do("PATCH", id, map[string]any{"authType": "password"}), http.StatusOK)
	e.expect(e.do("POST", id+"/deploy", nil), http.StatusOK)
	if e.dep.lastTarget.Password != "ssh-Pa55!web" || e.dep.lastTarget.PrivateKey != "" {
		t.Fatalf("password auth: %+v", e.dep.lastTarget)
	}
}

func TestTrapPortConflictsOnHost(t *testing.T) {
	e := newHostEnv(t)
	a := e.createHost(passwordHost("a", "10.0.0.1"))
	b := e.createHost(passwordHost("b", "10.0.0.2"))
	first := e.createTrap(sshTrap(a.ID, "SSH", 2222))
	if first.HostID == nil || *first.HostID != a.ID {
		t.Fatalf("hostId not set: %+v", first.HostID)
	}

	clash := func(w *httptest.ResponseRecorder, port string, trap string) {
		t.Helper()
		if w.Code != http.StatusConflict {
			t.Fatalf("want 409, got %d: %s", w.Code, w.Body.String())
		}
		m := decodeInto[map[string]any](t, w)
		if m["error"] != "port conflict" || m["port"] != port || m["trap"] != trap {
			t.Fatalf("conflict body: %v", m)
		}
	}

	banner := func(host any, port int, enabled bool) map[string]any {
		return map[string]any{"hostId": host, "name": "Banner", "class": "banner", "port": port,
			"params": map[string]any{"banner": "x"}, "enabled": enabled}
	}
	clash(e.do("POST", "/api/traps", banner(a.ID, 2222, true)), "2222/tcp", "SSH")

	// Тот же порт можно: на другом хосте, без хоста, выключенной ловушке, по UDP.
	e.createTrap(banner(b.ID, 2222, true))
	e.createTrap(banner(nil, 2222, true))
	off := e.createTrap(banner(a.ID, 2222, false))
	e.createTrap(map[string]any{"hostId": a.ID, "name": "DNS", "class": "udp", "port": 2222, "params": map[string]any{}, "enabled": true})

	// Включить выключенную на занятом порту — конфликт.
	clash(e.do("PATCH", fmt.Sprintf("/api/traps/%d", off.ID), map[string]any{"enabled": true}), "2222/tcp", "SSH")
	// А сменить порт и включить — можно.
	e.expect(e.do("PATCH", fmt.Sprintf("/api/traps/%d", off.ID), map[string]any{"enabled": true, "port": 2223}), http.StatusOK)

	// Порт внутри диапазона многопортовой ловушки.
	clash(e.do("POST", "/api/traps", map[string]any{"hostId": a.ID, "name": "Scan", "class": "port_listener",
		"ports": "2220-2225", "params": map[string]any{}, "enabled": true}), "2222/tcp", "SSH")

	// Перенос на хост, где порт занят.
	loose := e.createTrap(looseTrap("Loose", 2222))
	if loose.HostID != nil {
		t.Fatalf("trap without hostId must be unassigned: %v", *loose.HostID)
	}
	w := e.do("PATCH", fmt.Sprintf("/api/traps/%d", loose.ID), map[string]any{"hostId": a.ID})
	clash(w, "2222/tcp", "SSH")

	// Неизвестный хост.
	w = e.do("POST", "/api/traps", sshTrap(999, "x", 1))
	if w.Code != http.StatusBadRequest || errorOf(t, w) != "host not found" {
		t.Fatalf("unknown host: %d %s", w.Code, w.Body.String())
	}
	w = e.do("PATCH", fmt.Sprintf("/api/traps/%d", first.ID), map[string]any{"hostId": 999})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("move to unknown host: %d %s", w.Code, w.Body.String())
	}

	// Отвязка от хоста через null и сохранение порта самой ловушки (с собой не конфликтует).
	e.expect(e.do("PATCH", fmt.Sprintf("/api/traps/%d", first.ID), map[string]any{"port": 2222}), http.StatusOK)
	w = e.do("PATCH", fmt.Sprintf("/api/traps/%d", first.ID), map[string]any{"hostId": nil})
	e.expect(w, http.StatusOK)
	if tr := decodeInto[models.Trap](t, w); tr.HostID != nil {
		t.Fatalf("hostId must be cleared: %v", *tr.HostID)
	}
}

// hostId 0 — это не «без хоста» (для этого null или отсутствие поля), а несуществующий хост.
func TestTrapZeroHostIsUnknown(t *testing.T) {
	e := newHostEnv(t)
	w := e.do("POST", "/api/traps", sshTrap(0, "x", 2222))
	if w.Code != http.StatusBadRequest || errorOf(t, w) != "host not found" {
		t.Fatalf("hostId 0: %d %s", w.Code, w.Body.String())
	}
}

func TestDeployHostSendsAllEnabledTraps(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	other := e.createHost(passwordHost("db", "10.0.0.6"))
	t1 := e.createTrap(sshTrap(host.ID, "SSH", 2222))
	t2 := e.createTrap(map[string]any{"hostId": host.ID, "name": "FTP", "class": "dialog", "port": 2121,
		"params": map[string]any{"greeting": "220 hi\\r\\n"}, "enabled": true})
	e.createTrap(map[string]any{"hostId": host.ID, "name": "Off", "class": "banner", "port": 2323, "params": map[string]any{}, "enabled": false})
	e.createTrap(sshTrap(other.ID, "Elsewhere", 2222))
	e.createTrap(looseTrap("Loose", 2222))
	path := fmt.Sprintf("/api/hosts/%d", host.ID)

	if h := e.getHost(host.ID); h.DeployedAt != nil || h.PendingChanges || h.TrapCount != 3 || h.EnabledTraps != 2 {
		t.Fatalf("before deploy: %+v", h)
	}

	w := e.do("POST", path+"/deploy", nil)
	e.expect(w, http.StatusOK)
	resp := decodeInto[hostOpResponse](t, w)
	if resp.Status != "deployed" || resp.Traps != 2 || resp.Host != "10.0.0.5" || resp.DeployedAt == nil {
		t.Fatalf("response: %+v", resp)
	}

	// Конфиг агента: обе включённые ловушки, каждая со своими токеном и ключом.
	var cfg map[string]any
	if err := json.Unmarshal(e.dep.lastPayload.ConfigJSON, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["center_url"] != "http://center.example:8080" {
		t.Fatalf("center_url: %v", cfg["center_url"])
	}
	if _, ok := cfg["token"]; ok {
		t.Fatal("host config must not carry a root token")
	}
	if _, ok := cfg["trap"]; ok {
		t.Fatal("host config must use traps, not trap")
	}
	traps := cfg["traps"].([]any)
	if len(traps) != 2 {
		t.Fatalf("want 2 traps, got %d: %v", len(traps), traps)
	}
	for i, want := range []models.Trap{t1, t2} {
		got := traps[i].(map[string]any)
		full, _ := e.mem.GetTrap(context.Background(), want.ID)
		if got["token"] != full.Token || got["server_pub_key"] != full.PubKey || got["name"] != want.Name ||
			got["class"] != want.Class || int(got["port"].(float64)) != want.Port {
			t.Fatalf("trap %d in config: %v", i, got)
		}
		if full.Token == "" || full.PubKey == "" {
			t.Fatalf("trap %d has no token/key", i)
		}
	}
	if e.dep.lastTarget.Password != "ssh-Pa55!web" || e.dep.lastTarget.RootPassword != "sudo-Pa55!web" {
		t.Fatalf("decrypted target: %+v", e.dep.lastTarget)
	}

	// Сразу после деплоя изменений нет.
	h := e.getHost(host.ID)
	if h.DeployedAt == nil || h.PendingChanges {
		t.Fatalf("after deploy: %+v", h)
	}

	// Переименование ловушки не требует передеплоя, смена параметров — требует.
	e.expect(e.do("PATCH", fmt.Sprintf("/api/traps/%d", t1.ID), map[string]any{"name": "SSH renamed"}), http.StatusOK)
	if e.getHost(host.ID).PendingChanges {
		t.Fatal("rename must not mark the host as changed")
	}
	e.expect(e.do("PATCH", fmt.Sprintf("/api/traps/%d", t1.ID), map[string]any{"port": 2200}), http.StatusOK)
	if !e.getHost(host.ID).PendingChanges {
		t.Fatal("port change must mark the host as changed")
	}
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusOK)
	if e.getHost(host.ID).PendingChanges {
		t.Fatal("redeploy must clear pending changes")
	}
	// Удаление ловушки и выключение — тоже изменения.
	e.expect(e.do("DELETE", fmt.Sprintf("/api/traps/%d", t2.ID), nil), http.StatusNoContent)
	if !e.getHost(host.ID).PendingChanges {
		t.Fatal("deleting a trap must mark the host as changed")
	}
	// Изменения на другом хосте этот хост не трогают.
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusOK)
	e.createTrap(sshTrap(other.ID, "Another", 2201))
	if e.getHost(host.ID).PendingChanges {
		t.Fatal("other host's traps must not affect this host")
	}
}

func TestDeployHostErrors(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	path := fmt.Sprintf("/api/hosts/%d", host.ID)

	e.expect(e.do("POST", "/api/hosts/999/deploy", nil), http.StatusNotFound)

	// Без ловушек деплоить нечего.
	w := e.do("POST", path+"/deploy", nil)
	if w.Code != http.StatusConflict || errorOf(t, w) != "host has no enabled traps" {
		t.Fatalf("no traps: %d %s", w.Code, w.Body.String())
	}
	if e.dep.calls != 0 {
		t.Fatal("deployer must not be called without traps")
	}
	e.createTrap(sshTrap(host.ID, "SSH", 2222))

	// Ошибка SSH: текст ошибки доходит до оператора, хост не помечается развёрнутым.
	e.dep.deployFunc = func(context.Context, deploy.TargetConfig, deploy.Payload) error {
		return errors.New("ssh handshake failed with 10.0.0.5:22: unable to authenticate")
	}
	w = e.do("POST", path+"/deploy", nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(errorOf(t, w), "unable to authenticate") {
		t.Fatalf("deployer error: %d %s", w.Code, w.Body.String())
	}
	if e.getHost(host.ID).DeployedAt != nil {
		t.Fatal("failed deploy must not mark the host deployed")
	}
	e.dep.deployFunc = nil

	// Неудачное обновление с откатом: хост остаётся развёрнутым (работает прежняя версия).
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusOK)
	deployedAt := e.getHost(host.ID).DeployedAt
	e.dep.deployFunc = func(context.Context, deploy.TargetConfig, deploy.Payload) error {
		return errors.New("agent failed to start:\nport busy\nprevious version restored")
	}
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusBadGateway)
	if got := e.getHost(host.ID).DeployedAt; got == nil || !got.Equal(*deployedAt) {
		t.Fatalf("rolled back host must keep its deploy mark: %v", got)
	}
	// Откатиться было некуда — агент остановлен, хост больше не развёрнут.
	e.dep.deployFunc = func(context.Context, deploy.TargetConfig, deploy.Payload) error {
		return fmt.Errorf("agent failed to start:\nport busy\n%w: no previous working version to restore", deploy.ErrAgentStopped)
	}
	w = e.do("POST", path+"/deploy", nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(errorOf(t, w), "agent stopped") {
		t.Fatalf("stopped: %d %s", w.Code, w.Body.String())
	}
	if h := e.getHost(host.ID); h.DeployedAt != nil || h.PendingChanges {
		t.Fatalf("stopped agent must clear the deploy mark: %+v", h)
	}
	e.dep.deployFunc = nil

	// Вторая операция над тем же хостом, пока идёт первая, — отказ.
	unlock, ok := e.h.lockHost(httptest.NewRecorder(), host.ID)
	if !ok {
		t.Fatal("lock")
	}
	calls := e.dep.calls
	for _, op := range []string{"/deploy", "/undeploy"} {
		w = e.do("POST", path+op, nil)
		if w.Code != http.StatusConflict || errorOf(t, w) != "another operation on this host is in progress" {
			t.Fatalf("%s while busy: %d %s", op, w.Code, w.Body.String())
		}
	}
	if e.dep.calls != calls {
		t.Fatal("busy host must not reach the deployer")
	}
	unlock()
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusOK)

	// Ключ шифрования сменился — сохранённый пароль не расшифровать.
	e.h.Secrets = ephemeralBox()
	w = e.do("POST", path+"/deploy", nil)
	if w.Code != http.StatusConflict || errorOf(t, w) != "stored credentials cannot be decrypted; re-enter them" {
		t.Fatalf("undecryptable: %d %s", w.Code, w.Body.String())
	}
	// Повторный ввод пароля чинит хост.
	e.expect(e.do("PATCH", path, map[string]any{"password": "p1", "sudoPassword": "p2"}), http.StatusOK)
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusOK)

	// Сервер без бинарника агента.
	t.Setenv("HF_AGENT_BIN", filepath.Join(t.TempDir(), "missing"))
	w = e.do("POST", path+"/deploy", nil)
	if w.Code != http.StatusInternalServerError || errorOf(t, w) != "agent binary not found; please build the agent first" {
		t.Fatalf("missing binary: %d %s", w.Code, w.Body.String())
	}

	e.h.Deployer = nil
	w = e.do("POST", path+"/deploy", nil)
	if w.Code != http.StatusInternalServerError || errorOf(t, w) != "deployer service unavailable" {
		t.Fatalf("no deployer: %d %s", w.Code, w.Body.String())
	}
}

func TestUndeployAndDeleteHost(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	path := fmt.Sprintf("/api/hosts/%d", host.ID)
	tr := e.createTrap(sshTrap(host.ID, "SSH", 2222))
	e.expect(e.do("POST", path+"/deploy", nil), http.StatusOK)

	// Развёрнутый хост просто так не удалить: агент остался бы без управления.
	w := e.do("DELETE", path, nil)
	if w.Code != http.StatusConflict || errorOf(t, w) != "host is deployed; remove the agent first" {
		t.Fatalf("delete deployed: %d %s", w.Code, w.Body.String())
	}

	// Ошибка снятия оставляет отметку о развёртывании.
	e.dep.undeployFunc = func(context.Context, deploy.TargetConfig) error { return errors.New("connection refused") }
	w = e.do("POST", path+"/undeploy", nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(errorOf(t, w), "connection refused") {
		t.Fatalf("undeploy error: %d %s", w.Code, w.Body.String())
	}
	if e.getHost(host.ID).DeployedAt == nil {
		t.Fatal("failed undeploy must keep the deployed mark")
	}
	e.dep.undeployFunc = nil

	w = e.do("POST", path+"/undeploy", nil)
	e.expect(w, http.StatusOK)
	if r := decodeInto[hostOpResponse](t, w); r.Status != "removed" || r.HostID != host.ID {
		t.Fatalf("undeploy response: %+v", r)
	}
	if e.dep.lastAction != "undeploy" || e.dep.lastTarget.Password != "ssh-Pa55!web" {
		t.Fatalf("undeploy target: %s %+v", e.dep.lastAction, e.dep.lastTarget)
	}
	if h := e.getHost(host.ID); h.DeployedAt != nil || h.PendingChanges {
		t.Fatalf("after undeploy: %+v", h)
	}

	// Теперь удаляется; ловушка остаётся, но без хоста.
	e.expect(e.do("DELETE", path, nil), http.StatusNoContent)
	got, err := e.mem.GetTrap(context.Background(), tr.ID)
	if err != nil || got.HostID != nil {
		t.Fatalf("trap after host delete: %+v, %v", got, err)
	}
	e.expect(e.do("DELETE", path, nil), http.StatusNotFound)

	// force=true удаляет и развёрнутый хост (сервер уже недоступен навсегда).
	h2 := e.createHost(passwordHost("gone", "10.0.0.9"))
	e.createTrap(sshTrap(h2.ID, "SSH", 2222))
	e.expect(e.do("POST", fmt.Sprintf("/api/hosts/%d/deploy", h2.ID), nil), http.StatusOK)
	e.expect(e.do("DELETE", fmt.Sprintf("/api/hosts/%d?force=true", h2.ID), nil), http.StatusNoContent)
}

func TestHostStatusReportsMissingPorts(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	path := fmt.Sprintf("/api/hosts/%d/status", host.ID)
	e.createTrap(sshTrap(host.ID, "SSH", 2222))
	e.createTrap(map[string]any{"hostId": host.ID, "name": "FTP", "class": "dialog", "port": 2121, "params": map[string]any{}, "enabled": true})
	e.createTrap(map[string]any{"hostId": host.ID, "name": "DNS", "class": "udp", "port": 1053, "params": map[string]any{}, "enabled": true})
	e.createTrap(map[string]any{"hostId": host.ID, "name": "Off", "class": "banner", "port": 2323, "params": map[string]any{}, "enabled": false})

	e.dep.statusFunc = func(context.Context, deploy.TargetConfig) (*deploy.ServiceStatus, error) {
		return &deploy.ServiceStatus{Active: true, SubState: "active", Loaded: true, Listening: []int{22, 2222}}, nil
	}
	w := e.do("GET", path, nil)
	e.expect(w, http.StatusOK)
	st := decodeInto[hostStatusResponse](t, w)
	if !st.Active || st.HostID != host.ID {
		t.Fatalf("status: %+v", st)
	}
	if strings.Join(st.ExpectedPorts, ",") != "2222/tcp,2121/tcp,1053/udp" {
		t.Fatalf("expected ports: %v", st.ExpectedPorts)
	}
	// 2121 не слушается; UDP не проверяется (ss -t его не показывает); выключенная не ожидается.
	if strings.Join(st.MissingPorts, ",") != "2121/tcp" {
		t.Fatalf("missing ports: %v", st.MissingPorts)
	}

	// Агент не запущен — «пропавших» портов не считаем, статус говорит сам за себя.
	e.dep.statusFunc = func(context.Context, deploy.TargetConfig) (*deploy.ServiceStatus, error) {
		return &deploy.ServiceStatus{Active: false, SubState: "inactive"}, nil
	}
	st = decodeInto[hostStatusResponse](t, e.do("GET", path, nil))
	if st.Active || len(st.MissingPorts) != 0 || st.SubState != "inactive" {
		t.Fatalf("inactive: %+v", st)
	}

	e.dep.statusFunc = func(context.Context, deploy.TargetConfig) (*deploy.ServiceStatus, error) {
		return nil, errors.New("dial tcp 10.0.0.5:22: i/o timeout")
	}
	w = e.do("GET", path, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(errorOf(t, w), "i/o timeout") {
		t.Fatalf("status error: %d %s", w.Code, w.Body.String())
	}
}

func TestHostConfigDownload(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	path := fmt.Sprintf("/api/hosts/%d/config", host.ID)
	e.expect(e.do("GET", path, nil), http.StatusConflict) // ещё нет ловушек

	e.createTrap(sshTrap(host.ID, "SSH", 2222))
	w := e.do("GET", path, nil)
	e.expect(w, http.StatusOK)
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, fmt.Sprintf("honeyforge-host-%d.json", host.ID)) {
		t.Fatalf("Content-Disposition: %q", cd)
	}
	cfg := decodeInto[map[string]any](t, w)
	if len(cfg["traps"].([]any)) != 1 {
		t.Fatalf("config: %v", cfg)
	}
	// Скачивание ничего не меняет на хосте.
	if e.getHost(host.ID).DeployedAt != nil || e.dep.calls != 0 {
		t.Fatal("config download must not deploy")
	}
}

func TestTrapLevelDeployRefusedForHostedTrap(t *testing.T) {
	e := newHostEnv(t)
	host := e.createHost(passwordHost("web", "10.0.0.5"))
	tr := e.createTrap(sshTrap(host.ID, "SSH", 2222))
	body := map[string]any{"host": "10.0.0.5", "username": "root", "password": "x"}
	w := e.do("POST", fmt.Sprintf("/api/traps/%d/deploy", tr.ID), body)
	if w.Code != http.StatusConflict || errorOf(t, w) != "trap belongs to a host; deploy the host instead" {
		t.Fatalf("hosted trap deploy: %d %s", w.Code, w.Body.String())
	}
	if e.dep.calls != 0 {
		t.Fatal("deployer must not run")
	}
	// Ловушка без хоста разворачивается по-старому.
	loose := e.createTrap(looseTrap("Loose", 2222))
	e.expect(e.do("POST", fmt.Sprintf("/api/traps/%d/deploy", loose.ID), body), http.StatusOK)
}

func TestTrapsHashIgnoresJSONFormattingAndNames(t *testing.T) {
	a := []models.Trap{{ID: 1, Name: "A", Token: "t", Class: "ssh", Port: 22, Params: json.RawMessage(`{"b":1,"a":"x"}`)}}
	b := []models.Trap{{ID: 1, Name: "B", Token: "t", Class: "ssh", Port: 22, Params: json.RawMessage(`{ "a" : "x", "b" : 1 }`)}}
	if trapsHash(a) != trapsHash(b) {
		t.Fatal("hash must not depend on JSON formatting or name")
	}
	c := []models.Trap{{ID: 1, Token: "t", Class: "ssh", Port: 22, Params: json.RawMessage(`{"a":"y","b":1}`)}}
	if trapsHash(a) == trapsHash(c) {
		t.Fatal("hash must change with params")
	}
	if trapsHash(nil) == trapsHash(a) {
		t.Fatal("empty set must differ")
	}
}

func TestParsePortSpecMatchesAgent(t *testing.T) {
	for spec, want := range map[string]string{
		"8000-8002,9200": "[8000 8001 8002 9200]",
		" 22 , 22,21 ":   "[21 22]",
		"0,65535,70000":  "[65535]",
		"x,10-y,5":       "[5]",
		"65534-70000":    "[65534 65535]",
		"":               "[]",
	} {
		if got := fmt.Sprint(parsePortSpec(spec)); got != want {
			t.Errorf("parsePortSpec(%q) = %s, want %s", spec, got, want)
		}
	}
}
