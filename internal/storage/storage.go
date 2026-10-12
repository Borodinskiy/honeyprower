package storage

import (
	"context"
	"errors"
	"time"

	"honeyprower/internal/models"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// OnlineWindow — ловушка считается online, если присылала телеметрию не позже этого срока.
const OnlineWindow = 90 * time.Second

// Storage is the abstraction the handlers use.
// Swap Memory for Postgres / SQLite / Redis later without touching handlers.
type Storage interface {
	// --- traps ---
	ListTraps(ctx context.Context) ([]models.Trap, error)
	GetTrap(ctx context.Context, id int64) (*models.Trap, error)
	GetTrapByToken(ctx context.Context, token string) (*models.Trap, error)
	CreateTrap(ctx context.Context, in models.TrapCreate, token string) (*models.Trap, error)
	UpdateTrap(ctx context.Context, id int64, patch models.TrapPatch) (*models.Trap, error)
	DeleteTrap(ctx context.Context, id int64) error

	// --- events ---
	// InsertEvent stores one piece of telemetry and refreshes the trap's last-seen.
	InsertEvent(ctx context.Context, trapID int64, ev models.IngestEvent) (*models.Event, error)
	ListEvents(ctx context.Context, f models.EventFilter) ([]models.Event, error)

	// TouchTrap refreshes last-seen for a heartbeat (no event stored).
	TouchTrap(ctx context.Context, token string) error

	GetStats(ctx context.Context) (*models.Stats, error)

	// --- users ---
	CreateUser(ctx context.Context, u *models.User) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, id int64) (*models.User, error)
}

// trapStatus derives online/offline/never from last-seen.
func trapStatus(lastSeen *time.Time, now time.Time) string {
	if lastSeen == nil {
		return "never"
	}
	if now.Sub(*lastSeen) <= OnlineWindow {
		return "online"
	}
	return "offline"
}

// isWarning reports whether an event type is "attack-worthy" (counts toward warnings).
func isWarning(eventType string) bool {
	switch eventType {
	case "auth", "scan", "token":
		return true
	default:
		return false
	}
}
