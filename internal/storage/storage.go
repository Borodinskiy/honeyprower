package storage

import (
	"context"
	"errors"

	"honeyprower/internal/models"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// Storage is the abstraction the handlers use.
// Swap Memory for Postgres / SQLite / Redis later without touching handlers.
type Storage interface {
	ListTraps(ctx context.Context) ([]models.Trap, error)
	GetTrap(ctx context.Context, id int64) (*models.Trap, error)
	CreateTrap(ctx context.Context, in models.TrapCreate) (*models.Trap, error)
	UpdateTrap(ctx context.Context, id int64, patch models.TrapPatch) (*models.Trap, error)
	DeleteTrap(ctx context.Context, id int64) error

	ListEvents(ctx context.Context, trapID int64) ([]models.Event, error)

	GetStats(ctx context.Context) (*models.Stats, error)

	CreateUser(ctx context.Context, u *models.User) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, id int64) (*models.User, error)
}
