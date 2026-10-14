package handlers

// Хосты: серверы, на каждом из которых один агент держит все свои ловушки.
// Центр хранит SSH-доступ к хосту (зашифрованным) и по нему разворачивает,
// обновляет и снимает агента целиком.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"honeyprower/internal/deploy"
	"honeyprower/internal/httpx"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

const (
	maxHostNameLen  = 255
	maxSSHUserLen   = 64
	maxSecretLen    = 16 * 1024 // приватный RSA-4096 в PEM ~3.3 КБ
	hostStatusLimit = time.Minute
)

// hostnameRe — DNS-имя (RFC 1123): метки из букв, цифр и дефисов через точку.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// hostInput — тело POST/PATCH /api/hosts. Пароли и ключ приходят открытым
// текстом и сразу шифруются; пустое значение в PATCH — «не менять».
type hostInput struct {
	Name         *string `json:"name"`
	Address      *string `json:"address"`
	SSHPort      *int    `json:"sshPort"`
	Username     *string `json:"username"`
	AuthType     *string `json:"authType"`
	Password     *string `json:"password"`
	PrivateKey   *string `json:"privateKey"`
	UseSudo      *bool   `json:"useSudo"`
	SudoPassword *string `json:"sudoPassword"`
}

type hostOpResponse struct {
	Status     string     `json:"status"`
	HostID     int64      `json:"hostId"`
	Host       string     `json:"host"`
	Traps      int        `json:"traps,omitempty"`
	DeployedAt *time.Time `json:"deployedAt,omitempty"`
}

type hostStatusResponse struct {
	*deploy.ServiceStatus
	HostID int64 `json:"hostId"`
	// Порты включённых ловушек хоста и те из них (TCP), которые сейчас никто не слушает.
	ExpectedPorts []string `json:"expectedPorts"`
	MissingPorts  []string `json:"missingPorts"`
}

func (h *Handlers) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.Store.ListHosts(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load hosts")
		return
	}
	traps, err := h.Store.ListTraps(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load traps")
		return
	}
	for i := range hosts {
		fillHostView(&hosts[i], traps)
	}
	httpx.WriteJSON(w, http.StatusOK, hosts)
}

func (h *Handlers) GetHost(w http.ResponseWriter, r *http.Request) {
	host, traps, ok := h.loadHost(w, r)
	if !ok {
		return
	}
	fillHostView(host, traps)
	httpx.WriteJSON(w, http.StatusOK, host)
}

func (h *Handlers) CreateHost(w http.ResponseWriter, r *http.Request) {
	var in hostInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	host := models.Host{SSHPort: 22, Username: "root", AuthType: "password"}
	if msg := h.applyHostInput(&host, in); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	created, err := h.Store.CreateHost(r.Context(), host)
	if errors.Is(err, storage.ErrAlreadyExists) {
		httpx.WriteError(w, http.StatusConflict, "host with this address already exists")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create host")
		return
	}
	fillHostView(created, nil)
	httpx.WriteJSON(w, http.StatusCreated, created)
}

func (h *Handlers) UpdateHost(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in hostInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	cur, err := h.Store.GetHost(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load host")
		return
	}
	next := *cur
	if msg := h.applyHostInput(&next, in); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	updated, err := h.Store.UpdateHost(r.Context(), id, models.HostPatch{
		Name: &next.Name, Address: &next.Address, SSHPort: &next.SSHPort, Username: &next.Username,
		AuthType: &next.AuthType, UseSudo: &next.UseSudo, PasswordEnc: &next.PasswordEnc,
		PrivateKeyEnc: &next.PrivateKeyEnc, SudoPasswordEnc: &next.SudoPasswordEnc,
	})
	if errors.Is(err, storage.ErrAlreadyExists) {
		httpx.WriteError(w, http.StatusConflict, "host with this address already exists")
		return
	}
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update host")
		return
	}
	traps, _ := h.Store.ListTraps(r.Context())
	fillHostView(updated, traps)
	httpx.WriteJSON(w, http.StatusOK, updated)
}

// DeleteHost удаляет хост, его ловушки остаются без хоста. Развёрнутый хост
// удалить нельзя без ?force=true: агент на сервере продолжил бы работать, а
// снять его из центра стало бы нечем.
func (h *Handlers) DeleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	host, err := h.Store.GetHost(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load host")
		return
	}
	if host.DeployedAt != nil && r.URL.Query().Get("force") != "true" {
		httpx.WriteError(w, http.StatusConflict, "host is deployed; remove the agent first")
		return
	}
	if err := h.Store.DeleteHost(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "host not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete host")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HostConfig отдаёт config.json агента хоста — для ручного запуска без SSH.
func (h *Handlers) HostConfig(w http.ResponseWriter, r *http.Request) {
	host, traps, ok := h.loadHost(w, r)
	if !ok {
		return
	}
	active := deployableTraps(host.ID, traps)
	if len(active) == 0 {
		httpx.WriteError(w, http.StatusConflict, "host has no enabled traps")
		return
	}
	cfg := h.buildHostConfig(r, active)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="honeyforge-host-%d.json"`, host.ID))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(cfg)
}

// DeployHost ставит (или обновляет) агента хоста со всеми его включёнными ловушками.
func (h *Handlers) DeployHost(w http.ResponseWriter, r *http.Request) {
	host, traps, ok := h.loadHost(w, r)
	if !ok {
		return
	}
	unlock, ok := h.lockHost(w, host.ID)
	if !ok {
		return
	}
	defer unlock()

	active := deployableTraps(host.ID, traps)
	if len(active) == 0 {
		httpx.WriteError(w, http.StatusConflict, "host has no enabled traps")
		return
	}
	target, ok := h.hostTarget(w, host)
	if !ok {
		return
	}
	cfg := h.buildHostConfig(r, active)
	payload, status, msg := h.agentPayload(&cfg, target)
	if msg != "" {
		httpx.WriteError(w, status, msg)
		return
	}

	// Общий WriteTimeout сервера (15 с) оборвал бы ответ посреди деплоя.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(deployTimeout + 10*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), deployTimeout)
	defer cancel()
	if err := h.Deployer.Deploy(ctx, target, payload); err != nil {
		// Обновление не взлетело, а откатиться было не на что: агент на сервере остановлен,
		// и хост не должен выглядеть развёрнутым.
		if errors.Is(err, deploy.ErrAgentStopped) {
			_ = h.Store.SetHostDeployed(context.WithoutCancel(r.Context()), host.ID, nil, "")
		}
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Агент уже стоит — отметку пишем, даже если клиент успел отключиться.
	now := time.Now().UTC()
	if err := h.Store.SetHostDeployed(context.WithoutCancel(r.Context()), host.ID, &now, trapsHash(active)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "agent deployed, but failed to record it")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, hostOpResponse{
		Status: "deployed", HostID: host.ID, Host: host.Address, Traps: len(active), DeployedAt: &now,
	})
}

// UndeployHost останавливает агента хоста и удаляет его файлы с сервера.
func (h *Handlers) UndeployHost(w http.ResponseWriter, r *http.Request) {
	host, _, ok := h.loadHost(w, r)
	if !ok {
		return
	}
	unlock, ok := h.lockHost(w, host.ID)
	if !ok {
		return
	}
	defer unlock()

	target, ok := h.hostTarget(w, host)
	if !ok {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(deployTimeout + 10*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), deployTimeout)
	defer cancel()
	if err := h.Deployer.Undeploy(ctx, target); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := h.Store.SetHostDeployed(context.WithoutCancel(r.Context()), host.ID, nil, ""); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "agent removed, but failed to record it")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, hostOpResponse{Status: "removed", HostID: host.ID, Host: host.Address})
}

// HostStatus спрашивает у сервера по SSH, работает ли агент и какие порты слушаются.
func (h *Handlers) HostStatus(w http.ResponseWriter, r *http.Request) {
	host, traps, ok := h.loadHost(w, r)
	if !ok {
		return
	}
	target, ok := h.hostTarget(w, host)
	if !ok {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(hostStatusLimit + 10*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), hostStatusLimit)
	defer cancel()
	st, err := h.Deployer.Status(ctx, target)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	if st == nil {
		st = &deploy.ServiceStatus{}
	}

	resp := hostStatusResponse{ServiceStatus: st, HostID: host.ID, ExpectedPorts: []string{}, MissingPorts: []string{}}
	listening := map[string]bool{}
	for _, p := range st.Listening {
		listening[fmt.Sprintf("%d/tcp", p)] = true
	}
	for _, t := range deployableTraps(host.ID, traps) {
		for _, s := range trapSockets(&t) {
			resp.ExpectedPorts = append(resp.ExpectedPorts, s)
			// UDP-порты ss -tlpn не показывает — их отсутствие ничего не значит.
			if st.Active && strings.HasSuffix(s, "/tcp") && !listening[s] {
				resp.MissingPorts = append(resp.MissingPorts, s)
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------

// loadHost берёт хост из пути и все ловушки. При ошибке отвечает сам.
func (h *Handlers) loadHost(w http.ResponseWriter, r *http.Request) (*models.Host, []models.Trap, bool) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return nil, nil, false
	}
	host, err := h.Store.GetHost(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return nil, nil, false
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load host")
		return nil, nil, false
	}
	traps, err := h.Store.ListTraps(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load traps")
		return nil, nil, false
	}
	return host, traps, true
}

// lockHost не даёт двум операциям над одним хостом идти одновременно: два
// деплоя наперегонки оставили бы на сервере непонятно какой конфиг.
func (h *Handlers) lockHost(w http.ResponseWriter, id int64) (func(), bool) {
	v, _ := h.hostOps.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	if !mu.TryLock() {
		httpx.WriteError(w, http.StatusConflict, "another operation on this host is in progress")
		return nil, false
	}
	return mu.Unlock, true
}

// hostTarget расшифровывает SSH-доступ хоста. При ошибке отвечает сам.
func (h *Handlers) hostTarget(w http.ResponseWriter, host *models.Host) (deploy.TargetConfig, bool) {
	if h.Deployer == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "deployer service unavailable")
		return deploy.TargetConfig{}, false
	}
	open := func(enc string) (string, bool) {
		v, err := h.Secrets.Open(enc)
		if err != nil {
			// Ключ шифрования сменился (например, потерян data/secret.key) — нужно ввести доступ заново.
			httpx.WriteError(w, http.StatusConflict, "stored credentials cannot be decrypted; re-enter them")
			return "", false
		}
		return v, true
	}
	t := deploy.TargetConfig{Host: host.Address, Port: host.SSHPort, Username: host.Username, UseSudo: host.UseSudo}
	var ok bool
	if host.AuthType == "key" {
		if t.PrivateKey, ok = open(host.PrivateKeyEnc); !ok {
			return t, false
		}
	} else if t.Password, ok = open(host.PasswordEnc); !ok {
		return t, false
	}
	if host.UseSudo {
		if t.RootPassword, ok = open(host.SudoPasswordEnc); !ok {
			return t, false
		}
	}
	if t.Password == "" && t.PrivateKey == "" {
		httpx.WriteError(w, http.StatusConflict, "host has no saved credentials")
		return t, false
	}
	return t, true
}

// applyHostInput проверяет ввод и переносит его в host (секреты — зашифрованными).
// Возвращает сообщение об ошибке.
func (h *Handlers) applyHostInput(host *models.Host, in hostInput) string {
	if in.Name != nil {
		host.Name = strings.TrimSpace(*in.Name)
	}
	if host.Name == "" {
		return "name is required"
	}
	if utf8.RuneCountInString(host.Name) > maxHostNameLen {
		return "name is too long"
	}

	if in.Address != nil {
		host.Address = strings.TrimSpace(*in.Address)
	}
	if host.Address == "" {
		return "address is required"
	}
	if !validAddress(host.Address) {
		return "invalid address"
	}

	if in.SSHPort != nil {
		host.SSHPort = *in.SSHPort
	}
	if host.SSHPort < 1 || host.SSHPort > 65535 {
		return "ssh port must be 1..65535"
	}

	if in.Username != nil {
		host.Username = strings.TrimSpace(*in.Username)
	}
	if host.Username == "" {
		return "username is required"
	}
	if len(host.Username) > maxSSHUserLen || strings.ContainsFunc(host.Username, unicode.IsSpace) {
		return "invalid username"
	}

	if in.AuthType != nil {
		host.AuthType = *in.AuthType
	}
	if host.AuthType != "password" && host.AuthType != "key" {
		return "auth type must be password or key"
	}
	if in.UseSudo != nil {
		host.UseSudo = *in.UseSudo
	}

	// Секреты: непустое значение заменяет сохранённое, пустое — оставляет как было.
	set := func(dst *string, v *string) string {
		if v == nil || *v == "" {
			return ""
		}
		if len(*v) > maxSecretLen {
			return "secret is too long"
		}
		enc, err := h.Secrets.Seal(*v)
		if err != nil {
			return "failed to encrypt credentials"
		}
		*dst = enc
		return ""
	}
	if in.PrivateKey != nil && *in.PrivateKey != "" {
		key := strings.TrimSpace(*in.PrivateKey) + "\n"
		if msg := checkPrivateKey(key); msg != "" {
			return msg
		}
		in.PrivateKey = &key
	}
	for _, f := range []struct {
		dst *string
		v   *string
	}{{&host.PasswordEnc, in.Password}, {&host.PrivateKeyEnc, in.PrivateKey}, {&host.SudoPasswordEnc, in.SudoPassword}} {
		if msg := set(f.dst, f.v); msg != "" {
			return msg
		}
	}

	// Для выбранного способа входа секрет должен быть — новый или сохранённый.
	if host.AuthType == "password" && host.PasswordEnc == "" {
		return "password is required"
	}
	if host.AuthType == "key" && host.PrivateKeyEnc == "" {
		return "private key is required"
	}
	return ""
}

// checkPrivateKey проверяет ключ сразу при сохранении, а не при первом деплое.
func checkPrivateKey(key string) string {
	_, err := ssh.ParsePrivateKey([]byte(key))
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &missing):
		return "encrypted private keys are not supported"
	default:
		return "invalid private key"
	}
}

func validAddress(a string) bool {
	if len(a) > 253 {
		return false
	}
	if net.ParseIP(strings.Trim(a, "[]")) != nil {
		return true
	}
	return hostnameRe.MatchString(a)
}

// deployableTraps — включённые ловушки хоста по возрастанию id: ровно то, что
// попадёт в конфиг агента.
func deployableTraps(hostID int64, all []models.Trap) []models.Trap {
	var out []models.Trap
	for _, t := range all {
		if t.Enabled && t.HostID != nil && *t.HostID == hostID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// trapsHash — отпечаток того, что развёрнуто на хосте. Разошёлся с текущими
// ловушками — на сервере старая версия. Имя не входит: переименование не
// меняет поведения ловушки, и пересобирать агента ради него незачем.
func trapsHash(traps []models.Trap) string {
	type item struct {
		ID     int64           `json:"id"`
		Token  string          `json:"token"`
		PubKey string          `json:"pubKey"`
		Class  string          `json:"class"`
		Bind   string          `json:"bind"`
		Port   int             `json:"port"`
		Ports  string          `json:"ports"`
		Params json.RawMessage `json:"params"`
	}
	items := make([]item, 0, len(traps))
	for _, t := range traps {
		items = append(items, item{t.ID, t.Token, t.PubKey, t.Class, t.Bind, t.Port, t.Ports, canonicalJSON(t.Params)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	b, _ := json.Marshal(items)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON приводит JSON к одному виду (порядок ключей, пробелы): Postgres
// (jsonb) и память хранят параметры по-разному, а отпечаток должен совпадать.
func canonicalJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// fillHostView заполняет производные поля хоста по его ловушкам.
func fillHostView(host *models.Host, traps []models.Trap) {
	host.HasPassword = host.PasswordEnc != ""
	host.HasPrivateKey = host.PrivateKeyEnc != ""
	host.HasSudoPassword = host.SudoPasswordEnc != ""
	host.TrapCount, host.EnabledTraps, host.OnlineTraps = 0, 0, 0
	for _, t := range traps {
		if t.HostID == nil || *t.HostID != host.ID {
			continue
		}
		host.TrapCount++
		if t.Enabled {
			host.EnabledTraps++
		}
		if t.Status == "online" {
			host.OnlineTraps++
		}
	}
	host.PendingChanges = host.DeployedAt != nil && host.DeployedHash != trapsHash(deployableTraps(host.ID, traps))
}
