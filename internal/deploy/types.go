package deploy

import (
	"context"
	"encoding/json"
	"errors"

	"honeyprower/internal/pydeps"
)

// ErrAgentStopped: an update failed and the agent on the host is now stopped (there was no
// working version to roll back to). The host no longer runs any traps.
var ErrAgentStopped = errors.New("agent stopped")

// TargetConfig specifies the parameters required to connect to a target host
// via SSH and perform privileged installation tasks.
type TargetConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password,omitempty"`
	PrivateKey     string `json:"privateKey,omitempty"`
	RootPassword   string `json:"rootPassword,omitempty"`
	UseSudo        bool   `json:"useSudo,omitempty"`
	Action         string `json:"action,omitempty"`
	CheckPreflight bool   `json:"checkPreflight,omitempty"`
	CheckHealth    bool   `json:"checkHealth,omitempty"`
}

// UnmarshalJSON supports both camelCase and snake_case JSON field names.
func (t *TargetConfig) UnmarshalJSON(data []byte) error {
	type Alias TargetConfig
	aux := struct {
		*Alias
		AltPrivateKey     string `json:"private_key"`
		AltRootPassword   string `json:"root_password"`
		AltUseSudo        *bool  `json:"use_sudo"`
		AltCheckPreflight *bool  `json:"check_preflight"`
		AltCheckHealth    *bool  `json:"check_health"`
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if t.PrivateKey == "" && aux.AltPrivateKey != "" {
		t.PrivateKey = aux.AltPrivateKey
	}
	if t.RootPassword == "" && aux.AltRootPassword != "" {
		t.RootPassword = aux.AltRootPassword
	}
	if aux.AltUseSudo != nil && !t.UseSudo {
		t.UseSudo = *aux.AltUseSudo
	}
	if aux.AltCheckPreflight != nil && !t.CheckPreflight {
		t.CheckPreflight = *aux.AltCheckPreflight
	}
	if aux.AltCheckHealth != nil && !t.CheckHealth {
		t.CheckHealth = *aux.AltCheckHealth
	}
	return nil
}

// Payload contains the installation artifacts to deploy onto the remote server.
type Payload struct {
	BinaryPath     string `json:"binaryPath,omitempty"`
	ServiceContent []byte `json:"serviceContent,omitempty"`
	ConfigJSON     []byte `json:"configJson,omitempty"`
	// Plugins — свои ловушки, которые запускает агент из этого конфига.
	Plugins []PluginFiles `json:"-"`
}

// PluginFiles — проект своей ловушки: архив tar.gz и каталог на хосте, куда его
// распаковать (имя каталога включает хэш, поэтому одна версия ставится один раз).
type PluginFiles struct {
	Name     string
	Dir      string // абсолютный, например /opt/honeyforge/plugins/my-ftp-0123456789ab
	Archive  []byte
	Requires []string // команды, которые должны быть на хосте
	// PythonModules — модули, которые python3 на хосте должен импортировать.
	PythonModules []string
	// Packages — системные пакеты по менеджерам (apt, dnf, yum, apk, zypper).
	Packages map[string][]string
	// PyDeps собирает Python-зависимости (pip) под платформу хоста; nil — их нет.
	PyDeps func(ctx context.Context, p pydeps.Platform) ([]byte, error)
}

// ServiceStatus describes the runtime status of the remote agent service.
type ServiceStatus struct {
	Active    bool   `json:"active"`
	SubState  string `json:"subState"`
	Loaded    bool   `json:"loaded"`
	Listening []int  `json:"listeningPorts,omitempty"`
	// ListeningAll — все слушающие TCP-порты хоста: порт своей ловушки в режиме
	// service держит её программа, а не процесс агента.
	ListeningAll []int  `json:"listeningAllPorts,omitempty"`
	Uptime       string `json:"uptime,omitempty"`
	RawOutput    string `json:"rawOutput,omitempty"`
}

// Deployer abstracts remote agent installation, lifecycle operations, and removal.
type Deployer interface {
	Deploy(ctx context.Context, target TargetConfig, payload Payload) error
	Status(ctx context.Context, target TargetConfig) (*ServiceStatus, error)
	Restart(ctx context.Context, target TargetConfig) error
	Stop(ctx context.Context, target TargetConfig) error
	Uninstall(ctx context.Context, target TargetConfig) error
	// Undeploy stops the agent and removes its files from the target.
	Undeploy(ctx context.Context, target TargetConfig) error
}
