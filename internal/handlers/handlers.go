package handlers

import (
	"honeyprower/internal/auth"
	"honeyprower/internal/storage"
)

type Handlers struct {
	Store storage.Storage
	Auth  *auth.Manager
}

func New(s storage.Storage, a *auth.Manager) *Handlers {
	return &Handlers{Store: s, Auth: a}
}
