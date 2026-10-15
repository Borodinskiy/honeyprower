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
	Level         string          `json:"level"`     // Low | Medium | High | ICS/SCADA
	Transport     string          `json:"transport"` // tcp | udp
	MultiPort     bool            `json:"multiPort"`
	DefaultPort   int             `json:"defaultPort"`
	DefaultPorts  string          `json:"defaultPorts,omitempty"` // для многопортовых классов
	DefaultParams json.RawMessage `json:"defaultParams"`
	Fields        []Field         `json:"fields"` // описание параметров для формы

	// Только у своих ловушек (internal/plugin): откуда класс и какая версия загружена.
	Origin  string `json:"origin,omitempty"` // "plugin"
	Version string `json:"version,omitempty"`
	Mode    string `json:"mode,omitempty"` // service | stdio
	SHA256  string `json:"sha256,omitempty"`
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
		ID: "port_listener", Title: "Слушатель портов", Level: "Low", Transport: "tcp", MultiPort: true,
		Description:   "Открывает набор портов, логирует подключения и первые байты. Детектор сканирования: N портов от одного IP → событие scan.",
		DefaultPorts:  "9000-9003,10443",
		DefaultParams: raw(`{"action":"read_then_close","scan_threshold":3}`),
	},
	{
		ID: "banner", Title: "Баннер сервиса", Level: "Low", Transport: "tcp", DefaultPort: 2222,
		Description:   "Отправляет статический баннер и логирует ввод. Для протоколов, где сервер говорит первым (SSH, FTP, SMTP).",
		DefaultParams: raw(`{"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n","close_after_input":true}`),
	},
	{
		ID: "ssh", Title: "SSH-сервер (OpenSSH)", Level: "Medium", Transport: "tcp", DefaultPort: 2222,
		Description:   "Настоящий SSH-протокол: обмен ключами, шифрование, вход по паролю и ключу. Записывает логины, пароли и отпечатки ключей, отвечает «Permission denied». Клиент не отличит от OpenSSH.",
		DefaultParams: raw(`{"version":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10","max_auth_tries":6,"fail_delay_ms":"1800-2600"}`),
	},
	{
		ID: "dialog", Title: "Диалоговый автомат", Level: "Medium", Transport: "tcp", DefaultPort: 2121,
		Description:   "Текстовый протокол по regex-правилам: захват логинов, паролей, команд. Собирает FTP, SMTP, POP3, IMAP, Telnet, Redis.",
		DefaultParams: raw(`{"greeting":"220 {hostname} ready\r\n","decoder":"line","default_response":"500 Unknown command\r\n","rules":[{"match":"^USER\\s+(.*)$","response":"331 Please specify the password.\r\n","capture":"username"},{"match":"^PASS\\s?(.*)$","response":"530 Login incorrect.\r\n","capture":"password"},{"match":"^QUIT","response":"221 Bye\r\n","close":true}]}`),
	},
	{
		ID: "http", Title: "HTTP-приманка", Level: "Medium", Transport: "tcp", DefaultPort: 8080,
		Description:   "Веб-сервер-приманка на маршрутах. Логирует запросы, ловит логины из форм, JSON и HTTP Basic.",
		DefaultParams: raw(`{"server_header":"Apache/2.4.58 (Ubuntu)","routes":[{"path":"^/$","method":"*","status":200,"body":"<html><body><h1>It works!</h1></body></html>"},{"path":"^/(wp-admin|admin|login)","method":"*","status":200,"capture_login":true,"tag":"admin-login","body":"<form method=post><input name=username><input name=password type=password></form>"}]}`),
	},
	{
		ID: "tarpit", Title: "Tarpit (замедлитель)", Level: "Low", Transport: "tcp", DefaultPort: 2223,
		Description:   "Удерживает клиента, отдавая байты по капле (как endlessh). Тратит время сканеров и брутфорсеров.",
		DefaultParams: raw(`{"mode":"ssh_banner","delay_ms":10000,"max_hold_s":3600}`),
	},
	{
		ID: "honeytoken", Title: "Honeytoken (приёмник ссылок)", Level: "Medium", Transport: "tcp", DefaultPort: 8088,
		Description:   "HTTP-приёмник ссылок-приманок: переход по уникальной ссылке → событие token.",
		DefaultParams: raw(`{"tokens":[{"label":"share/finance/README.html","token":""}]}`),
	},
	{
		ID: "udp", Title: "UDP-ответчик", Level: "Low", Transport: "udp", DefaultPort: 1053,
		Description:   "UDP-сервис: DNS, NTP, SSDP, SIP или правила. Логирует датаграммы, ограничивает отражённое усиление.",
		DefaultParams: raw(`{"helper":"dns","dns_answer_ip":"10.0.0.15","limit_amplification":true,"max_replies_per_ip_min":20}`),
	},
	{
		ID: "iec104", Title: "IEC 60870-5-104 (МЭК 104)", Level: "ICS/SCADA", Transport: "tcp", DefaultPort: 2404,
		Description:   "Промышленный протокол телемеханики подстанций АСУ ТП. Поддержка APCI/ASDU, STARTDT/STOPDT, общего опроса C_IC_NA_1 и команд телеуправления C_SC_NA_1/C_DC_NA_1.",
		DefaultParams: raw(`{"breaker_closed":true,"switch_closed":true,"voltage":220.5,"power":45.2,"frequency":50.0}`),
	},
	{
		ID: "scada", Title: "SCADA & Modbus TCP", Level: "ICS/SCADA", Transport: "tcp", DefaultPort: 502,
		Description:   "Контроллер Modbus TCP (чтение/запись регистров и койлов, MEI идентификация устройства) и веб-интерфейс диспетчера SCADA Web HMI.",
		DefaultParams: raw(`{"vendor_name":"Schneider Electric","product_code":"Modicon M580","revision":"v4.10"}`),
	},
	{
		ID: "high_interaction", Title: "High-Interaction VFS Sandbox", Level: "High", Transport: "tcp", DefaultPort: 2222,
		Description:   "Полноценная интерактивная оболочка Linux с изменяемой виртуальной ФС (VFS), скрытием процесса агента, honeytoken-приманками и расчётом SHA-256 полезной нагрузки.",
		DefaultParams: raw(`{"hostname":"substation-gw01","user":"root","banner":"Linux substation-gw01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64\r\n\r\n"}`),
	},
	{
		ID: "low_extra", Title: "Расширенный сетевой зонд", Level: "Low", Transport: "tcp", DefaultPort: 1900,
		Description:   "Детектор сетевого сканирования и эмулятор сетевых протоколов обнаружения (SSDP, Daytime, Chargen, Echo).",
		DefaultParams: raw(`{"mode":"auto","device_location":"http://127.0.0.1:1900/rootDesc.xml","device_usn":"uuid:honeyforge-upnp-device-01","server_header":"Linux/4.14 UPnP/1.0"}`),
	},
	{
		ID: "medium_extra", Title: "Приманка БД / MQTT Telemetry", Level: "Medium", Transport: "tcp", DefaultPort: 6379,
		Description:   "Эмулятор сетевых сервисов: Redis сервер (PING/AUTH/INFO/CONFIG) и брокер промышленной телеметрии MQTT (CONNECT/SUBSCRIBE/PUBLISH).",
		DefaultParams: raw(`{"mode":"auto","redis_version":"7.0.12"}`),
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
