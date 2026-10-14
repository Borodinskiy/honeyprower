package deploy

import (
	"context"
	"encoding/json"
)

// TargetConfig specifies the parameters required to connect to a target host
// via SSH and perform privileged installation tasks.
type TargetConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	PrivateKey   string `json:"privateKey,omitempty"`
	RootPassword string `json:"rootPassword,omitempty"`
	UseSudo      bool   `json:"useSudo,omitempty"`
}

// UnmarshalJSON supports both camelCase and snake_case JSON field names.
func (t *TargetConfig) UnmarshalJSON(data []byte) error {
	type Alias TargetConfig
	aux := struct {
		*Alias
		AltPrivateKey   string `json:"private_key"`
		AltRootPassword string `json:"root_password"`
		AltUseSudo      *bool  `json:"use_sudo"`
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
	return nil
}

// Payload contains the installation artifacts to deploy onto the remote server.
type Payload struct {
	BinaryPath     string `json:"binaryPath,omitempty"`
	ServiceContent []byte `json:"serviceContent,omitempty"`
	ConfigJSON     []byte `json:"configJson,omitempty"`
}

// Deployer abstracts remote agent installation.
type Deployer interface {
	Deploy(ctx context.Context, target TargetConfig, payload Payload) error
}
