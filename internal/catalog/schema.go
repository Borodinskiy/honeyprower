package catalog

// Field describes one trap parameter. The site builds the create/edit form
// from these descriptions, and ValidateParams checks incoming params with them.
type Field struct {
	Key         string   `json:"key"`
	Title       string   `json:"title"`
	Type        string   `json:"type"` // string | text | int | number | bool | enum | list
	Default     any      `json:"default,omitempty"`
	Help        string   `json:"help,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Advanced    bool     `json:"advanced,omitempty"` // прячется в «Дополнительно»
	Options     []Option `json:"options,omitempty"`  // для enum
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	Regex       bool     `json:"regex,omitempty"` // значение — регулярное выражение
	Hex         bool     `json:"hex,omitempty"`   // значение — байты в hex
	ShowIf      *Cond    `json:"showIf,omitempty"`

	// Для list: поля одного элемента, как назвать элемент и какие поля
	// показывать в свёрнутом заголовке элемента.
	Item      []Field  `json:"item,omitempty"`
	ItemTitle string   `json:"itemTitle,omitempty"`
	Summary   []string `json:"summary,omitempty"`
}

// Option is one value of an enum field.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Cond shows a field only when a sibling field has one of the listed values.
type Cond struct {
	Key string   `json:"key"`
	In  []string `json:"in"`
}

// --- конструкторы, чтобы описания классов читались как таблица ---

func str(key, title string, def string, help string) Field {
	return Field{Key: key, Title: title, Type: "string", Default: def, Help: help}
}

func text(key, title string, def string, help string) Field {
	return Field{Key: key, Title: title, Type: "text", Default: def, Help: help}
}

func integer(key, title string, def int, help string, min, max float64) Field {
	return Field{Key: key, Title: title, Type: "int", Default: def, Help: help, Min: &min, Max: &max}
}

func number(key, title string, def float64, help string, min, max float64) Field {
	return Field{Key: key, Title: title, Type: "number", Default: def, Help: help, Min: &min, Max: &max}
}

func boolean(key, title string, def bool, help string) Field {
	return Field{Key: key, Title: title, Type: "bool", Default: def, Help: help}
}

func enum(key, title, def, help string, opts ...Option) Field {
	return Field{Key: key, Title: title, Type: "enum", Default: def, Help: help, Options: opts}
}

func opt(value, label string) Option { return Option{Value: value, Label: label} }

func list(key, title, itemTitle, help string, summary []string, item ...Field) Field {
	return Field{Key: key, Title: title, Type: "list", Help: help, ItemTitle: itemTitle, Summary: summary, Item: item}
}

func (f Field) adv() Field        { f.Advanced = true; return f }
func (f Field) re() Field         { f.Regex = true; return f }
func (f Field) hex() Field        { f.Hex = true; return f }
func (f Field) ph(p string) Field { f.Placeholder = p; return f }
func (f Field) when(key string, in ...string) Field {
	f.ShowIf = &Cond{Key: key, In: in}
	return f
}

const escHelp = `\r\n — перевод строки, \xNN — байт, {hostname} / {src_ip} — подстановки.`

// Общие параметры TCP-ловушек (агент читает их одинаково для всех классов).
var (
	pIdle  = number("idle_timeout", "Таймаут простоя, с", 30, "Молчащий клиент отключается через столько секунд.", 1, 86400).adv()
	pBytes = integer("max_session_bytes", "Макс. байт от клиента за сессию", 65536, "Защита от заливки мусором: после лимита сессия закрывается.", 1024, 16<<20).adv()
	pConns = integer("max_clients", "Макс. одновременных клиентов", 200, "Лишние подключения сразу закрываются.", 1, 10000).adv()
	pDelay = str("response_delay_ms", "Задержка ответа, мс", "0", "«50» — всегда 50 мс, «30-120» — случайно в диапазоне. Мгновенные ответы выдают эмулятор.").adv()
	pHost  = str("hostname", "Имя хоста", "srv01", "Подставляется вместо {hostname} в ответах.").adv()
)

var schemas = map[string][]Field{
	"port_listener": {
		enum("action", "Действие после подключения", "read_then_close",
			"«Прочитать и закрыть» — видно, что прислал сканер (часто это выдаёт инструмент).",
			opt("read_then_close", "Прочитать первые байты и закрыть"),
			opt("close", "Сразу закрыть"),
			opt("hold", "Держать до таймаута")),
		integer("scan_threshold", "Порог сканирования: разных портов", 3,
			"Сколько разных портов должен тронуть один IP, чтобы появилось событие «сканирование».", 2, 1000),
		number("read_window_s", "Сколько ждать первые байты, с", 3, "", 0.1, 60).adv().when("action", "read_then_close"),
		number("scan_window_s", "Окно детектора сканирования, с", 60, "", 1, 3600).adv(),
		pIdle.when("action", "hold"), pConns,
	},
	"banner": {
		text("banner", "Баннер", `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n`,
			"Ровно то, что клиент увидит сразу после подключения. "+escHelp),
		boolean("close_after_input", "Закрыть после первого ввода", false,
			"Для SSH-баннера: записать версию клиента и разорвать соединение."),
		str("after_input", "Ответ на любой ввод", "", "Пусто — молчать и только записывать."),
		str("banner_hex", "Баннер в hex (заменяет текстовый)", "",
			"Для бинарных протоколов (VNC, RDP): например 524642203030332e3030380a.").hex().adv(),
		pHost, pIdle, pBytes, pConns, pDelay,
	},
	"dialog": {
		text("greeting", "Приветствие сервера", `220 {hostname} ready\r\n`,
			"Первая строка сервера. Пусто — сервер молчит, пока клиент не напишет (как Redis). "+escHelp),
		enum("decoder", "Разбор входа", "line",
			"Построчно — FTP, SMTP, POP3, IMAP. Telnet — убирает служебные байты. RESP — протокол Redis.",
			opt("line", "Построчно"), opt("telnet", "Telnet"), opt("resp", "Redis RESP")),
		str("default_response", "Ответ, если ни одно правило не подошло", `500 Unknown command\r\n`, escHelp),
		list("rules", "Правила ответа", "Правило",
			"Каждая строка клиента проверяется по правилам сверху вниз; срабатывает первое совпавшее.",
			[]string{"match", "response"},
			str("match", "Если клиент прислал (regex)", "", `Регистр не важен. ^USER\s+(.*)$ — команда USER, (.*) — её аргумент.`).re().ph(`^USER\s+(.*)$`),
			str("response", "Ответить", "", `{1} — первая скобка из regex, {username}, {hostname}. `+escHelp).ph(`331 Password required\r\n`),
			enum("capture", "Записать как", "", "Скобки можно назвать: (?P<user>...) и (?P<pass>...).",
				opt("", "ничего особого"), opt("username", "логин (1-я скобка)"), opt("password", "пароль (1-я скобка)"),
				opt("username_password", "логин и пароль (1-я и 2-я скобки)"), opt("command", "команду")),
			boolean("close", "Закрыть соединение после ответа", false, ""),
			enum("decode", "Декодировать захват", "", "",
				opt("", "нет"), opt("base64", "base64"), opt("sasl_plain", "SASL PLAIN")).adv().when("capture", "username", "password", "username_password"),
			str("state", "Только в состоянии", "*", "* — в любом. Состояния задают порядок шагов: например, пароль принимается только после логина.").adv(),
			str("next_state", "Перейти в состояние", "", "").adv(),
			boolean("log", "Писать в журнал как команду", true, "").adv(),
		),
		pHost,
		str("initial_state", "Начальное состояние", "start", "").adv(),
		integer("max_commands", "Макс. команд за сессию", 100, "", 1, 100000).adv(),
		pIdle, pBytes, pConns, pDelay,
	},
	"http": {
		str("server_header", "Заголовок Server", "Apache/2.4.58 (Ubuntu)", "Так сервер представляется сканерам (curl -I покажет именно это)."),
		str("basic_auth_realm", "HTTP Basic realm", "", "Если задать — на любой путь ответ 401 и окно входа браузера; введённое записывается."),
		list("routes", "Страницы (маршруты)", "Маршрут",
			"Путь запроса проверяется сверху вниз; срабатывает первый совпавший маршрут.",
			[]string{"method", "path", "status"},
			str("path", "Путь (regex)", "^/$", "^/$ — главная, ^/admin — всё под /admin. Query-строка не учитывается.").re(),
			enum("method", "Метод", "*", "",
				opt("*", "любой"), opt("GET", "GET"), opt("POST", "POST"), opt("PUT", "PUT"),
				opt("DELETE", "DELETE"), opt("HEAD", "HEAD"), opt("OPTIONS", "OPTIONS")),
			integer("status", "Статус", 200, "", 100, 599),
			text("body", "Тело ответа", "<html><body>It works!</body></html>", "Подстановки: {path}, {src_ip}, {username}."),
			boolean("capture_login", "Ловить логин/пароль из формы или JSON", false, ""),
			str("tag", "Метка в журнале", "", "Например wp-login — по ней удобно фильтровать события."),
			str("content_type", "Content-Type", "text/html; charset=UTF-8", "").adv(),
			text("headers", "Доп. заголовки (K: V, по строке)", "", "Например Location: /login для редиректа (статус 302).").adv(),
		),
		text("not_found_body", "Тело ответа 404", "<h1>Not Found</h1>", "Ответ на путь, не подошедший ни к одному маршруту.").adv(),
		text("extra_headers", "Доп. заголовки во всех ответах", "", "K: V, по одному на строку.").adv(),
		str("user_fields", "Поля логина", "username,user,login,email,log,uname,name", "Имена полей формы/JSON, которые считаются логином.").adv(),
		str("pass_fields", "Поля пароля", "password,pass,pwd,passwd,secret", "Имена полей формы/JSON, которые считаются паролем.").adv(),
		pIdle, pBytes, pConns, pDelay,
	},
	"tarpit": {
		enum("mode", "Режим", "ssh_banner", "SSH-баннер держит ssh-клиенты и брутфорсеры, HTTP-заголовки — веб-сканеры.",
			opt("ssh_banner", "Бесконечный SSH-баннер"), opt("http_headers", "Бесконечные HTTP-заголовки"), opt("silent", "Молчать")),
		integer("delay_ms", "Пауза между строками, мс", 10000, "Чем больше пауза, тем дольше висит клиент. endlessh по умолчанию — 10 000 мс.", 10, 600000),
		integer("max_hold_s", "Макс. время удержания, с", 3600, "", 1, 86400),
		integer("max_line_length", "Макс. длина строки", 32, "", 3, 255).adv().when("mode", "ssh_banner", "http_headers"),
		pConns,
	},
	"honeytoken": {
		list("tokens", "Ссылки-приманки", "Ссылка",
			"Любой запрос, в котором встретится ID токена, даёт событие «Honeytoken». Положите ссылку туда, куда легитимный пользователь не заглядывает.",
			[]string{"label", "token"},
			str("label", "Где лежит (метка)", "", "Например share/finance/README.html — чтобы понять, какая приманка сработала.").ph("share/finance/README.html"),
			str("token", "ID токена", "", "Пусто — сгенерируется при сохранении."),
		),
		text("response_body", "Что отдать по ссылке", "<html><body></body></html>", "Пустая страница не вызывает подозрений.").adv(),
		pIdle, pConns,
	},
	"udp": {
		enum("helper", "Протокол", "none", "Готовый разбор протокола. «Только правила» — отвечать по правилам ниже.",
			opt("none", "Только правила"), opt("dns", "DNS (любое имя → IP)"), opt("ntp", "NTP (сервер времени)"),
			opt("ssdp", "SSDP (UPnP)"), opt("sip", "SIP (OPTIONS/REGISTER)")),
		str("dns_answer_ip", "IP в ответах", "10.0.0.15", "DNS отвечает этим адресом на любое имя; SSDP указывает его в LOCATION.").when("helper", "dns", "ssdp"),
		integer("ntp_stratum", "NTP stratum", 2, "1 — «эталонный» сервер (GPS), 2–3 — обычный.", 1, 15).when("helper", "ntp"),
		str("ssdp_server", "Server / User-Agent", "Linux/4.14 UPnP/1.0 MiniUPnPd/2.1", "").when("helper", "ssdp", "sip"),
		list("rules", "Правила ответа", "Правило",
			"Срабатывают, если протокол не ответил сам. Запрос проверяется сверху вниз по hex-префиксу или regex.",
			[]string{"match_regex", "match_hex"},
			str("match_regex", "Regex по тексту запроса", "", "").re(),
			str("match_hex", "Hex-префикс запроса", "", "").hex(),
			str("response", "Ответ (текст)", "", escHelp),
			str("response_hex", "Ответ (hex, заменяет текст)", "", "").hex().adv(),
		),
		boolean("limit_amplification", "Не отвечать больше запроса", true, "Не даёт использовать ловушку для DDoS-усиления (кроме DNS/NTP).").adv(),
		integer("max_replies_per_ip_min", "Макс. ответов одному IP в минуту", 20, "", 1, 10000).adv(),
		pDelay,
	},
}

// Schema returns the parameter description of a class (nil for unknown).
func Schema(classID string) []Field { return schemas[classID] }
