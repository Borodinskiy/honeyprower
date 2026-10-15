package models

// Структуры для де/кодирования из/в json

import (
	"encoding/json"
	"time"
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"-"`
}

// Host is a server that runs one agent with all of its traps. The center keeps
// its SSH access to deploy, update and remove that agent.
type Host struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"` // IP or DNS name for SSH
	SSHPort  int    `json:"sshPort"`
	Username string `json:"username"`
	AuthType string `json:"authType"` // password | key
	UseSudo  bool   `json:"useSudo"`

	// Encrypted with secret.Box; never sent to the browser.
	PasswordEnc     string `json:"-"`
	PrivateKeyEnc   string `json:"-"`
	SudoPasswordEnc string `json:"-"`

	// When the agent with the current set of traps was last installed (nil — not deployed).
	DeployedAt   *time.Time `json:"deployedAt,omitempty"`
	DeployedHash string     `json:"-"` // fingerprint of the traps that were deployed
	CreatedAt    time.Time  `json:"createdAt"`

	// Read-side, filled by the handlers:
	HasPassword     bool `json:"hasPassword"`
	HasPrivateKey   bool `json:"hasPrivateKey"`
	HasSudoPassword bool `json:"hasSudoPassword"`
	TrapCount       int  `json:"trapCount"`
	EnabledTraps    int  `json:"enabledTraps"`
	OnlineTraps     int  `json:"onlineTraps"`
	PendingChanges  bool `json:"pendingChanges"` // traps changed since the last deploy
}

// HostPatch updates a host; nil fields stay as they are.
type HostPatch struct {
	Name            *string
	Address         *string
	SSHPort         *int
	Username        *string
	AuthType        *string
	UseSudo         *bool
	PasswordEnc     *string
	PrivateKeyEnc   *string
	SudoPasswordEnc *string
}

// OptionalID tells an absent JSON field from an explicit null:
// {"hostId": null} unassigns the trap, a missing hostId leaves it alone.
type OptionalID struct {
	Set bool
	ID  *int64
}

func (o *OptionalID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.ID = nil
		return nil
	}
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	o.ID = &v
	return nil
}

// Trap is a honeypot definition the operator creates on the site. A Rust agent
// runs it from a generated config and streams events back, matched by Token.
type Trap struct {
	ID        int64           `json:"id"`
	HostID    *int64          `json:"hostId"` // nil — not assigned to a host
	Name      string          `json:"name"`
	Class     string          `json:"class"`
	Bind      string          `json:"bind"`
	Port      int             `json:"port"`
	Ports     string          `json:"ports,omitempty"`
	Params    json.RawMessage `json:"params"`
	Token     string          `json:"token,omitempty"` // shown so the operator can build the agent config
	KeyID     string          `json:"keyId,omitempty"`
	PubKey    string          `json:"pubKey,omitempty"`
	PrivKey   string          `json:"-"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"createdAt"`

	// Read-side, derived from telemetry:
	Status      string     `json:"status"` // online | offline | never
	LastSeen    *time.Time `json:"lastSeen,omitempty"`
	TotalEvents int        `json:"totalEvents"`
	Warnings    int        `json:"warnings"`
	LastEventAt string     `json:"lastEventAt"`
}

// TrapCreate is the body for POST /api/traps.
type TrapCreate struct {
	HostID  *int64          `json:"hostId,omitempty"`
	Name    string          `json:"name"`
	Class   string          `json:"class"`
	Bind    string          `json:"bind"`
	Port    int             `json:"port"`
	Ports   string          `json:"ports"`
	Params  json.RawMessage `json:"params"`
	KeyID   string          `json:"keyId,omitempty"`
	PubKey  string          `json:"pubKey,omitempty"`
	PrivKey string          `json:"-"`
	Enabled bool            `json:"enabled"`
}

// TrapPatch is the body for PATCH /api/traps/{id} (all fields optional).
type TrapPatch struct {
	HostID  OptionalID       `json:"hostId"`
	Name    *string          `json:"name,omitempty"`
	Bind    *string          `json:"bind,omitempty"`
	Port    *int             `json:"port,omitempty"`
	Ports   *string          `json:"ports,omitempty"`
	Params  *json.RawMessage `json:"params,omitempty"`
	KeyID   *string          `json:"keyId,omitempty"`
	PubKey  *string          `json:"pubKey,omitempty"`
	PrivKey *string          `json:"-"`
	Enabled *bool            `json:"enabled,omitempty"`
}

type Stats struct {
	ActiveTraps int `json:"activeTraps"` // enabled traps
	OnlineTraps int `json:"onlineTraps"` // seen recently
	Warnings24h int `json:"warnings24h"` // auth/scan/token events in last 24h
	TotalEvents int `json:"totalEvents"`
}

// Event is one piece of telemetry from a trap.
type Event struct {
	ID       int64           `json:"id"`
	TrapID   int64           `json:"trapId"`
	TrapName string          `json:"trapName,omitempty"`
	Class    string          `json:"class,omitempty"`
	Type     string          `json:"type"`
	Proto    string          `json:"proto"`
	Source   string          `json:"source"` // src_ip
	SrcPort  int             `json:"srcPort"`
	DstPort  int             `json:"dstPort"`
	Session  string          `json:"session,omitempty"`
	Username *string         `json:"username,omitempty"`
	Password *string         `json:"password,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	TS       float64         `json:"ts"`
	Time     string          `json:"time"` // formatted for the UI
}

// IngestEvent is the wire shape the agent POSTs to /api/ingest.
type IngestEvent struct {
	TrapClass string          `json:"trap_class"`
	EventType string          `json:"event_type"`
	Proto     string          `json:"proto"`
	SrcIP     string          `json:"src_ip"`
	SrcPort   int             `json:"src_port"`
	DstPort   int             `json:"dst_port"`
	Session   string          `json:"session"`
	Username  *string         `json:"username"`
	Password  *string         `json:"password"`
	Data      json.RawMessage `json:"data"`
	TS        float64         `json:"ts"`
}

// EventFilter narrows GET /api/events (FR-C4).
type EventFilter struct {
	TrapID    int64
	EventType string
	SrcIP     string
	SinceTS   float64
	Limit     int
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  *User  `json:"user"`
}

// Dashboard — агрегаты событий за окно [Since, Until) для графиков на главной.
type Dashboard struct {
	Since         float64 `json:"since"`
	Until         float64 `json:"until"`
	BucketSeconds int     `json:"bucketSeconds"`
	Events        int     `json:"events"`        // всего событий в окне
	Warnings      int     `json:"warnings"`      // из них auth/scan/token
	UniqueSources int     `json:"uniqueSources"` // разных IP-источников

	Timeline     []TimeBucket  `json:"timeline"` // по порядку, без пропусков, пустые ведра — нули
	ByType       []KeyCount    `json:"byType"`
	ByTrap       []TrapCount   `json:"byTrap"`
	TopSources   []SourceCount `json:"topSources"`
	TopUsernames []KeyCount    `json:"topUsernames"`
	TopPasswords []KeyCount    `json:"topPasswords"`
}

// TimeBucket — события одного интервала времени, TS — его начало.
type TimeBucket struct {
	TS       float64 `json:"ts"`
	Events   int     `json:"events"`
	Warnings int     `json:"warnings"`
}

type KeyCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type TrapCount struct {
	TrapID   int64  `json:"trapId"`
	Name     string `json:"name"`
	Events   int    `json:"events"`
	Warnings int    `json:"warnings"`
}

type SourceCount struct {
	IP       string  `json:"ip"`
	Events   int     `json:"events"`
	Warnings int     `json:"warnings"`
	Traps    int     `json:"traps"` // сколько разных ловушек задел
	LastTS   float64 `json:"lastTs"`
}
