package deploy

import (
	"context"
	"encoding/json"
)

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
}

// ServiceStatus describes the runtime status of the remote agent service.
type ServiceStatus struct {
	Active    bool   `json:"active"`
	SubState  string `json:"subState"`
	Loaded    bool   `json:"loaded"`
	Listening []int  `json:"listeningPorts,omitempty"`
	Uptime    string `json:"uptime,omitempty"`
	RawOutput string `json:"rawOutput,omitempty"`
}

// Deployer abstracts remote agent installation and lifecycle operations.
type Deployer interface {
	Deploy(ctx context.Context, target TargetConfig, payload Payload) error
	Status(ctx context.Context, target TargetConfig) (*ServiceStatus, error)
	Restart(ctx context.Context, target TargetConfig) error
	Stop(ctx context.Context, target TargetConfig) error
	Uninstall(ctx context.Context, target TargetConfig) error
}
