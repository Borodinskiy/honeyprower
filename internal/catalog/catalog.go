// Package catalog describes the honeypot trap classes the Rust agent can run
// and ships ready-made presets. It drives the "create trap" form on the site
// and provides the default params the operator edits.
package catalog

import (
	"embed"
	"encoding/json"
	"sort"
)

//go:embed presets/*.json
var presetFS embed.FS

// Class is one trap mechanism supported by the agent.
type Class struct {
	ID            string          `json:"id"`
	Title         string          `json:"title"`
	Description   string          `json:"description"`
	Transport     string          `json:"transport"` // tcp | udp
	MultiPort     bool            `json:"multiPort"`
	DefaultPort   int             `json:"defaultPort"`
	DefaultPorts  string          `json:"defaultPorts,omitempty"` // для многопортовых классов
	DefaultParams json.RawMessage `json:"defaultParams"`
	Fields        []Field         `json:"fields"` // описание параметров для формы
}

// Preset is a ready-made trap configuration (class + params).
type Preset struct {
	PresetID    string          `json:"presetId"`
	Name        string          `json:"name"`
	Class       string          `json:"class"`
	Port        int             `json:"port"`
	Ports       string          `json:"ports,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Description string          `json:"description"`
	Params      json.RawMessage `json:"params"`
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

// classes is the canonical list, mirroring the Rust agent's trap classes.
var classes = []Class{
	{
		ID: "port_listener", Title: "Слушатель портов", Transport: "tcp", MultiPort: true,
		Description:   "Открывает набор портов, логирует подключения и первые байты. Детектор сканирования: N портов от одного IP → событие scan.",
		DefaultPorts:  "9000-9003,10443",
		DefaultParams: raw(`{"action":"read_then_close","scan_threshold":3}`),
	},
	{
		ID: "banner", Title: "Баннер сервиса", Transport: "tcp", DefaultPort: 2222,
		Description:   "Отправляет статический баннер и логирует ввод. Для протоколов, где сервер говорит первым (SSH, FTP, SMTP).",
		DefaultParams: raw(`{"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n","close_after_input":true}`),
	},
	{
		ID: "ssh", Title: "SSH-сервер (OpenSSH)", Transport: "tcp", DefaultPort: 2222,
		Description:   "Настоящий SSH-протокол: обмен ключами, шифрование, вход по паролю и ключу. Записывает логины, пароли и отпечатки ключей, отвечает «Permission denied». Клиент не отличит от OpenSSH.",
		DefaultParams: raw(`{"version":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10","max_auth_tries":6,"fail_delay_ms":"1800-2600"}`),
	},
	{
		ID: "dialog", Title: "Диалоговый автомат", Transport: "tcp", DefaultPort: 2121,
		Description:   "Текстовый протокол по regex-правилам: захват логинов, паролей, команд. Собирает FTP, SMTP, POP3, IMAP, Telnet, Redis.",
		DefaultParams: raw(`{"greeting":"220 {hostname} ready\r\n","decoder":"line","default_response":"500 Unknown command\r\n","rules":[{"match":"^USER\\s+(.*)$","response":"331 Please specify the password.\r\n","capture":"username"},{"match":"^PASS\\s?(.*)$","response":"530 Login incorrect.\r\n","capture":"password"},{"match":"^QUIT","response":"221 Bye\r\n","close":true}]}`),
	},
	{
		ID: "http", Title: "HTTP-приманка", Transport: "tcp", DefaultPort: 8080,
		Description:   "Веб-сервер-приманка на маршрутах. Логирует запросы, ловит логины из форм, JSON и HTTP Basic.",
		DefaultParams: raw(`{"server_header":"Apache/2.4.58 (Ubuntu)","routes":[{"path":"^/$","method":"*","status":200,"body":"<html><body><h1>It works!</h1></body></html>"},{"path":"^/(wp-admin|admin|login)","method":"*","status":200,"capture_login":true,"tag":"admin-login","body":"<form method=post><input name=username><input name=password type=password></form>"}]}`),
	},
	{
		ID: "tarpit", Title: "Tarpit (замедлитель)", Transport: "tcp", DefaultPort: 2223,
		Description:   "Удерживает клиента, отдавая байты по капле (как endlessh). Тратит время сканеров и брутфорсеров.",
		DefaultParams: raw(`{"mode":"ssh_banner","delay_ms":10000,"max_hold_s":3600}`),
	},
	{
		ID: "honeytoken", Title: "Honeytoken (приёмник ссылок)", Transport: "tcp", DefaultPort: 8088,
		Description:   "HTTP-приёмник ссылок-приманок: переход по уникальной ссылке → событие token.",
		DefaultParams: raw(`{"tokens":[{"label":"share/finance/README.html","token":""}]}`),
	},
	{
		ID: "udp", Title: "UDP-ответчик", Transport: "udp", DefaultPort: 1053,
		Description:   "UDP-сервис: DNS, NTP, SSDP, SIP или правила. Логирует датаграммы, ограничивает отражённое усиление.",
		DefaultParams: raw(`{"helper":"dns","dns_answer_ip":"10.0.0.15","limit_amplification":true,"max_replies_per_ip_min":20}`),
	},
}

// Classes returns the trap-class catalog with parameter schemas attached.
func Classes() []Class {
	out := make([]Class, len(classes))
	copy(out, classes)
	for i := range out {
		out[i].Fields = Schema(out[i].ID)
	}
	return out
}

// ClassIDs is the set of known class ids.
func ClassIDs() map[string]bool {
	m := make(map[string]bool, len(classes))
	for _, c := range classes {
		m[c.ID] = true
	}
	return m
}

// ClassByID returns the class or false.
func ClassByID(id string) (Class, bool) {
	for _, c := range classes {
		if c.ID == id {
			return c, true
		}
	}
	return Class{}, false
}

// Presets loads and parses the embedded preset files, sorted by name.
func Presets() []Preset {
	entries, err := presetFS.ReadDir("presets")
	if err != nil {
		return nil
	}
	var out []Preset
	for _, e := range entries {
		data, err := presetFS.ReadFile("presets/" + e.Name())
		if err != nil {
			continue
		}
		// Файлы из прототипа: {name,class,port,params,tags,description,...}.
		var raw struct {
			Name        string          `json:"name"`
			Class       string          `json:"class"`
			Port        int             `json:"port"`
			Tags        []string        `json:"tags"`
			Description string          `json:"description"`
			Params      json.RawMessage `json:"params"`
		}
		if json.Unmarshal(data, &raw) != nil {
			continue
		}
		id := e.Name()
		id = id[:len(id)-len(".json")]
		params, ports := splitPorts(raw.Params)
		out = append(out, Preset{
			PresetID:    id,
			Name:        raw.Name,
			Class:       raw.Class,
			Port:        raw.Port,
			Tags:        raw.Tags,
			Description: raw.Description,
			Ports:       ports,
			Params:      params,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// splitPorts moves params.ports (prototype presets) out into the trap's own
// ports field, where the center keeps it.
func splitPorts(params json.RawMessage) (json.RawMessage, string) {
	var obj map[string]any
	if json.Unmarshal(params, &obj) != nil {
		return params, ""
	}
	ports, _ := obj["ports"].(string)
	if ports == "" {
		return params, ""
	}
	delete(obj, "ports")
	out, err := json.Marshal(obj)
	if err != nil {
		return params, ""
	}
	return out, ports
}
