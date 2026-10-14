package storage

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"honeyprower/internal/models"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	// ErrNoSuchHost — ловушку привязывают к хосту, которого нет.
	ErrNoSuchHost = errors.New("host does not exist")
)

// OnlineWindow — ловушка считается online, если присылала телеметрию не позже этого срока.
const OnlineWindow = 120 * time.Second

// Storage is the abstraction the handlers use.
// Swap Memory for Postgres / SQLite / Redis later without touching handlers.
type Storage interface {
	// --- hosts ---
	ListHosts(ctx context.Context) ([]models.Host, error)
	GetHost(ctx context.Context, id int64) (*models.Host, error)
	// CreateHost returns ErrAlreadyExists if another host has the same address and SSH port.
	CreateHost(ctx context.Context, h models.Host) (*models.Host, error)
	UpdateHost(ctx context.Context, id int64, patch models.HostPatch) (*models.Host, error)
	// DeleteHost removes the host; its traps stay, unassigned.
	DeleteHost(ctx context.Context, id int64) error
	// SetHostDeployed records a deploy (at != nil) or removal (at == nil) of the host's agent.
	SetHostDeployed(ctx context.Context, id int64, at *time.Time, hash string) error

	// --- traps ---
	ListTraps(ctx context.Context) ([]models.Trap, error)
	GetTrap(ctx context.Context, id int64) (*models.Trap, error)
	GetTrapByToken(ctx context.Context, token string) (*models.Trap, error)
	GetTrapByKeyID(ctx context.Context, keyID string) (*models.Trap, error)
	// CreateTrap and UpdateTrap return ErrNoSuchHost for an unknown HostID.
	CreateTrap(ctx context.Context, in models.TrapCreate, token string) (*models.Trap, error)
	UpdateTrap(ctx context.Context, id int64, patch models.TrapPatch) (*models.Trap, error)
	DeleteTrap(ctx context.Context, id int64) error

	// --- events ---
	// InsertEvent stores one piece of telemetry and refreshes the trap's last-seen.
	InsertEvent(ctx context.Context, trapID int64, ev models.IngestEvent) (*models.Event, error)
	ListFilterEvents(ctx context.Context, f models.EventFilter) ([]models.Event, error)

	// TouchTrap refreshes last-seen for a heartbeat (no event stored).
	TouchTrap(ctx context.Context, token string) error

	GetStats(ctx context.Context) (*models.Stats, error)

	// --- users ---
	CreateUser(ctx context.Context, u *models.User) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, id int64) (*models.User, error)
}

// hostKey normalizes what makes two hosts the same server.
func hostKey(address string, port int) string {
	return strings.ToLower(strings.TrimSpace(address)) + "|" + strconv.Itoa(port)
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
