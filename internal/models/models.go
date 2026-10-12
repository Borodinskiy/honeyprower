package models

import "time"

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"-"`
}

type Trap struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Target      string `json:"target"`
	Active      bool   `json:"active"`
	Warnings    int    `json:"warnings"`
	TotalEvents int    `json:"totalEvents"`
	LastEventAt string `json:"lastEventAt"`
}

// TrapCreate is the body for POST /api/traps
type TrapCreate struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Target string `json:"target"`
	Active bool   `json:"active"`
}

// TrapPatch is the body for PATCH /api/traps/{id} (all fields optional)
type TrapPatch struct {
	Name   *string `json:"name,omitempty"`
	Type   *string `json:"type,omitempty"`
	Target *string `json:"target,omitempty"`
	Active *bool   `json:"active,omitempty"`
}

type Stats struct {
	ActiveTraps int `json:"activeTraps"`
	Warnings24h int `json:"warnings24h"`
	ActiveTasks int `json:"activeTasks"`
}

type Event struct {
	ID     int64  `json:"id"`
	Type   string `json:"type"` // connection | auth | scan
	Source string `json:"source"`
	Time   string `json:"time"`
	Detail string `json:"detail"`
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
