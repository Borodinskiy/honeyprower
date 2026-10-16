// Package plugin — свои ловушки: проект пользователя, загруженный в центр
// архивом с манифестом honeyforge-plugin.json. Агент запускает его как
// дочерний процесс (см. agent/src/traps/plugin.rs), центр показывает его
// как ещё один класс ловушки "plugin:<name>".
package plugin

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"honeyprower/internal/catalog"
)

// ManifestFile — имя манифеста в корне архива.
const ManifestFile = "honeyforge-plugin.json"

// ClassPrefix — классы плагинов в центре называются "plugin:<name>".
const ClassPrefix = "plugin:"

// Manifest описывает, как запускать проект и какие у него параметры.
type Manifest struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
	// Mode: "service" — программа сама слушает порт; "stdio" — порт слушает агент
	// и на каждое соединение запускает программу со stdin/stdout = соединение.
	Mode      string   `json:"mode"`
	Transport string   `json:"transport"`
	Command   []string `json:"command"`
	// DefaultPort подставляется в форму новой ловушки.
	DefaultPort int `json:"default_port,omitempty"`
	// Requires — команды, которые должны быть на хосте (python3, node...): деплой проверит заранее.
	Requires []string `json:"requires,omitempty"`
	// PythonModules — модули Python, которые программа импортирует (paramiko...):
	// деплой проверит, что python3 на хосте их находит. python3 добавляется в Requires сам.
	PythonModules []string `json:"python_modules,omitempty"`
	// Pip — зависимости из PyPI (paramiko>=3.4...). Центр скачивает колёса под
	// платформу каждого хоста и привозит их сам: хосту не нужны ни pip, ни интернет.
	Pip []string `json:"pip,omitempty"`
	// Packages — системные пакеты по менеджерам (apt, dnf, yum, apk, zypper):
	// при развёртывании центр ставит недостающие из репозиториев хоста.
	Packages map[string][]string `json:"packages,omitempty"`
	// Params — поля формы параметров, в том же формате, что у встроенных классов.
	Params        []catalog.Field `json:"params,omitempty"`
	DefaultParams map[string]any  `json:"default_params,omitempty"`
}

// PackageManagers — менеджеры пакетов, для которых манифест может перечислить пакеты.
var PackageManagers = []string{"apt", "dnf", "yum", "apk", "zypper"}

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	requireRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	pipRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?(\s*(==|!=|<=|>=|~=|<|>)\s*[A-Za-z0-9.*+!-]+(\s*,\s*(==|!=|<=|>=|~=|<|>)\s*[A-Za-z0-9.*+!-]+)*)?$`)
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:-]{0,127}$`)
	moduleRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)
	keyRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

var fieldTypes = map[string]bool{"string": true, "text": true, "int": true, "number": true, "bool": true, "enum": true, "list": true}

// ParseManifest читает и проверяет манифест, заполняя значения по умолчанию.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %v", ManifestFile, err)
	}
	if err := m.normalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	return &m, nil
}

func (m *Manifest) normalize() error {
	m.Name = strings.TrimSpace(m.Name)
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("name: латиница в нижнем регистре, цифры, - и _, до 40 символов (например my-ftp)")
	}
	m.Title = strings.TrimSpace(m.Title)
	if m.Title == "" {
		m.Title = m.Name
	}
	if utf8.RuneCountInString(m.Title) > 80 {
		return fmt.Errorf("title: не длиннее 80 символов")
	}
	if utf8.RuneCountInString(m.Description) > 2000 {
		return fmt.Errorf("description: не длиннее 2000 символов")
	}
	if utf8.RuneCountInString(m.Version) > 32 {
		return fmt.Errorf("version: не длиннее 32 символов")
	}
	if m.Mode == "" {
		m.Mode = "service"
	}
	if m.Mode != "service" && m.Mode != "stdio" {
		return fmt.Errorf("mode: service (программа сама слушает порт) или stdio (соединение — это stdin/stdout)")
	}
	if m.Transport == "" {
		m.Transport = "tcp"
	}
	if m.Transport != "tcp" && m.Transport != "udp" {
		return fmt.Errorf("transport: tcp или udp")
	}
	if m.Mode == "stdio" && m.Transport != "tcp" {
		return fmt.Errorf("mode stdio работает только с transport tcp")
	}
	if len(m.Command) == 0 || strings.TrimSpace(m.Command[0]) == "" {
		return fmt.Errorf("command: укажите, как запускать программу, например [\"python3\", \"server.py\"]")
	}
	if len(m.Command) > 32 {
		return fmt.Errorf("command: не больше 32 аргументов")
	}
	for _, a := range m.Command {
		if len(a) > 1024 || strings.ContainsRune(a, 0) {
			return fmt.Errorf("command: слишком длинный или недопустимый аргумент")
		}
	}
	if _, err := m.CommandFile(); err != nil {
		return err
	}
	if m.DefaultPort < 0 || m.DefaultPort > 65535 {
		return fmt.Errorf("default_port: 1..65535")
	}
	if len(m.Requires) > 16 {
		return fmt.Errorf("requires: не больше 16 команд")
	}
	for _, r := range m.Requires {
		if !requireRe.MatchString(r) {
			return fmt.Errorf("requires: %q — имя команды, например python3", r)
		}
	}
	if len(m.PythonModules) > 32 {
		return fmt.Errorf("python_modules: не больше 32 модулей")
	}
	for _, mod := range m.PythonModules {
		if !moduleRe.MatchString(mod) {
			return fmt.Errorf("python_modules: %q — имя модуля, например paramiko", mod)
		}
	}
	if len(m.Pip) > 32 {
		return fmt.Errorf("pip: не больше 32 зависимостей")
	}
	for _, r := range m.Pip {
		if len(r) > 200 || !pipRe.MatchString(r) {
			return fmt.Errorf("pip: %q — зависимость в формате pip, например paramiko>=3.4", r)
		}
	}
	for mgr, pkgs := range m.Packages {
		if !slices.Contains(PackageManagers, mgr) {
			return fmt.Errorf("packages: неизвестный менеджер %q, допустимы %s", mgr, strings.Join(PackageManagers, ", "))
		}
		if len(pkgs) > 32 {
			return fmt.Errorf("packages.%s: не больше 32 пакетов", mgr)
		}
		for _, name := range pkgs {
			if !pkgRe.MatchString(name) {
				return fmt.Errorf("packages.%s: %q — имя пакета", mgr, name)
			}
		}
	}
	if (len(m.PythonModules) > 0 || len(m.Pip) > 0) && !slices.Contains(m.Requires, "python3") {
		m.Requires = append(m.Requires, "python3")
	}
	if err := validateSchema(m.Params, "params", true); err != nil {
		return err
	}
	if m.Mode == "stdio" {
		m.Params = withRuntimeFields(m.Params)
	}
	if m.DefaultParams != nil {
		if err := catalog.ValidateFields(m.Params, m.DefaultParams); err != nil {
			return fmt.Errorf("default_params: %w", err)
		}
	}
	return nil
}

// CommandFile — путь к программе внутри архива, если команда на неё указывает
// ("./run.sh", "bin/server"); пусто — программа ищется в PATH или задана абсолютно.
func (m *Manifest) CommandFile() (string, error) {
	first := m.Command[0]
	if !strings.Contains(first, "/") || strings.HasPrefix(first, "/") {
		return "", nil
	}
	clean := path.Clean(first)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("command: %q выходит за пределы каталога плагина", first)
	}
	return clean, nil
}

// validateSchema проверяет описание полей формы: те же правила, что у встроенных классов.
func validateSchema(fields []catalog.Field, where string, allowList bool) error {
	if len(fields) > 100 {
		return fmt.Errorf("%s: не больше 100 полей", where)
	}
	seen := map[string]bool{}
	for i, f := range fields {
		at := fmt.Sprintf("%s[%d]", where, i)
		if !keyRe.MatchString(f.Key) {
			return fmt.Errorf("%s.key: латиница, цифры и _, начинается с буквы", at)
		}
		at = fmt.Sprintf("%s (%s)", at, f.Key)
		if seen[f.Key] {
			return fmt.Errorf("%s: ключ повторяется", at)
		}
		seen[f.Key] = true
		if strings.TrimSpace(f.Title) == "" {
			return fmt.Errorf("%s.title: обязательно", at)
		}
		if !fieldTypes[f.Type] {
			return fmt.Errorf("%s.type: string, text, int, number, bool, enum или list", at)
		}
		if f.Type == "enum" && len(f.Options) == 0 {
			return fmt.Errorf("%s.options: у enum должны быть варианты", at)
		}
		if f.Type == "list" {
			if !allowList {
				return fmt.Errorf("%s: списки внутри списков не поддерживаются", at)
			}
			if len(f.Item) == 0 {
				return fmt.Errorf("%s.item: опишите поля элемента списка", at)
			}
			if err := validateSchema(f.Item, at+".item", false); err != nil {
				return err
			}
		} else if len(f.Item) > 0 {
			return fmt.Errorf("%s.item: только у type list", at)
		}
		if f.Min != nil && f.Max != nil && *f.Min > *f.Max {
			return fmt.Errorf("%s: min больше max", at)
		}
		if f.ShowIf != nil && !seen[f.ShowIf.Key] {
			return fmt.Errorf("%s.showIf: поле %q должно идти раньше", at, f.ShowIf.Key)
		}
		if f.Default != nil {
			if err := catalog.ValidateFields([]catalog.Field{f}, map[string]any{f.Key: f.Default}); err != nil {
				return fmt.Errorf("%s.default: %v", at, err)
			}
		}
	}
	return nil
}

// withRuntimeFields добавляет параметры, которые в режиме stdio читает сам агент
// (таймаут простоя и лимит клиентов), если плагин их не описал.
func withRuntimeFields(fields []catalog.Field) []catalog.Field {
	have := map[string]bool{}
	for _, f := range fields {
		have[f.Key] = true
	}
	minIdle, maxIdle := 1.0, 86400.0
	minConns, maxConns := 1.0, 10000.0
	out := append([]catalog.Field(nil), fields...)
	if !have["idle_timeout"] {
		out = append(out, catalog.Field{Key: "idle_timeout", Title: "Таймаут простоя, с", Type: "number", Default: 30.0,
			Help: "Молчащий клиент отключается через столько секунд.", Advanced: true, Min: &minIdle, Max: &maxIdle})
	}
	if !have["max_clients"] {
		out = append(out, catalog.Field{Key: "max_clients", Title: "Макс. одновременных клиентов", Type: "int", Default: 50.0,
			Help: "На каждого клиента запускается отдельный процесс; лишние подключения сразу закрываются.", Advanced: true, Min: &minConns, Max: &maxConns})
	}
	return out
}

// ClassID — класс ловушки этого плагина в центре.
func (m *Manifest) ClassID() string { return ClassPrefix + m.Name }

// NameFromClass возвращает имя плагина для класса "plugin:<name>".
func NameFromClass(class string) (string, bool) {
	if !strings.HasPrefix(class, ClassPrefix) {
		return "", false
	}
	return strings.TrimPrefix(class, ClassPrefix), true
}

// Class — описание для формы ловушки, как у встроенных классов.
func (m *Manifest) Class(sha string) catalog.Class {
	defaults := map[string]any{}
	for _, f := range m.Params {
		if f.Default != nil && f.Type != "list" {
			defaults[f.Key] = f.Default
		}
	}
	for k, v := range m.DefaultParams {
		defaults[k] = v
	}
	raw, _ := json.Marshal(defaults)
	desc := m.Description
	if desc == "" {
		desc = "Своя ловушка: " + m.Title
	}
	return catalog.Class{
		ID:            m.ClassID(),
		Title:         m.Title,
		Description:   desc,
		Level:         "Custom",
		Transport:     m.Transport,
		DefaultPort:   m.DefaultPort,
		DefaultParams: raw,
		Fields:        m.Params,
		Origin:        "plugin",
		Version:       m.Version,
		Mode:          m.Mode,
		SHA256:        sha,
	}
}
