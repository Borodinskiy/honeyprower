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

	// AddDemoEvents stores generated demo events without touching the traps' last-seen.
	AddDemoEvents(ctx context.Context, events []DemoEvent) error
	// DeleteDemoEvents removes every demo event and returns how many were removed.
	DeleteDemoEvents(ctx context.Context) (int, error)

	// TouchTrap refreshes last-seen for a heartbeat (no event stored).
	TouchTrap(ctx context.Context, token string) error

	GetStats(ctx context.Context) (*models.Stats, error)

	// --- plugins (свои ловушки) ---
	ListPlugins(ctx context.Context) ([]models.Plugin, error)
	GetPlugin(ctx context.Context, name string) (*models.Plugin, error)
	GetPluginArchive(ctx context.Context, name string) ([]byte, error)
	// SavePlugin добавляет плагин или заменяет загруженный ранее с тем же именем.
	SavePlugin(ctx context.Context, p models.Plugin, archive []byte) (*models.Plugin, error)
	DeletePlugin(ctx context.Context, name string) error
	// GetDashboard aggregates events of the last window, split into buckets of the given size;
	// buckets are aligned to local time of the given UTC offset.
	GetDashboard(ctx context.Context, window, bucket, utcOffset time.Duration) (*models.Dashboard, error)

	// --- users ---
	CreateUser(ctx context.Context, u *models.User) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, id int64) (*models.User, error)
}

// DemoSessionPrefix marks demo events: their session starts with it.
// Agents never produce it, so demo events can be removed without touching real ones.
const DemoSessionPrefix = "demo-"

// DemoEvent is one generated event of the demo traffic (see internal/demo).
type DemoEvent struct {
	TrapID int64
	Event  models.IngestEvent
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
