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

// Trap is a honeypot definition the operator creates on the site. A Rust agent
// runs it from a generated config and streams events back, matched by Token.
type Trap struct {
	ID        int64           `json:"id"`
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
