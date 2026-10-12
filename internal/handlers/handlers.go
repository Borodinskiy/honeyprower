package handlers

import (
	"honeyprower/internal/auth"
	"honeyprower/internal/storage"
)

type Handlers struct {
	Store storage.Storage
	Auth  *auth.Manager
	// AllowRegistration разрешает самостоятельную регистрацию через /api/auth/register.
	AllowRegistration bool
}

func New(s storage.Storage, a *auth.Manager) *Handlers {
	return &Handlers{Store: s, Auth: a, AllowRegistration: true}
}
