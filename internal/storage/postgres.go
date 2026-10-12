package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"honeyprower/internal/models"
	"honeyprower/migrations"
)

type Postgres struct {
	db *sql.DB
}

var _ Storage = (*Postgres)(nil)

// NewPostgres initializes a PostgreSQL connection, verifies it with Ping,
// auto-applies the schema migrations and seeds initial data if tables are empty.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	p := &Postgres{db: db}
	if err := p.initSchemaAndSeed(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return p, nil
}

func (p *Postgres) initSchemaAndSeed(ctx context.Context) error {
	if _, err := p.db.ExecContext(ctx, migrations.SchemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	var userCount int
	if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		return fmt.Errorf("check users count: %w", err)
	}

	var trapCount int
	if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM traps").Scan(&trapCount); err != nil {
		return fmt.Errorf("check traps count: %w", err)
	}

	if userCount == 0 && trapCount == 0 {
		if _, err := p.db.ExecContext(ctx, migrations.SeedSQL); err != nil {
			return fmt.Errorf("apply seed: %w", err)
		}
	}

	return nil
}

func (p *Postgres) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

// ---------------- traps ----------------

func (p *Postgres) ListTraps(ctx context.Context) ([]models.Trap, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, name, type, target, active, warnings, total_events, last_event_at
		FROM traps
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var traps []models.Trap
	for rows.Next() {
		var t models.Trap
		var lastEventAt sql.NullTime
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Type, &t.Target, &t.Active, &t.Warnings, &t.TotalEvents, &lastEventAt,
		); err != nil {
			return nil, err
		}
		t.LastEventAt = formatLastEvent(lastEventAt)
		traps = append(traps, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if traps == nil {
		traps = []models.Trap{}
	}
	return traps, nil
}

func (p *Postgres) GetTrap(ctx context.Context, id int64) (*models.Trap, error) {
	var t models.Trap
	var lastEventAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		SELECT id, name, type, target, active, warnings, total_events, last_event_at
		FROM traps
		WHERE id = $1
	`, id).Scan(
		&t.ID, &t.Name, &t.Type, &t.Target, &t.Active, &t.Warnings, &t.TotalEvents, &lastEventAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.LastEventAt = formatLastEvent(lastEventAt)
	return &t, nil
}

func (p *Postgres) CreateTrap(ctx context.Context, in models.TrapCreate) (*models.Trap, error) {
	var t models.Trap
	var lastEventAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		INSERT INTO traps (name, type, target, active, last_event_at)
		VALUES ($1, $2, $3, $4, NULL)
		RETURNING id, name, type, target, active, warnings, total_events, last_event_at
	`, in.Name, in.Type, in.Target, in.Active).Scan(
		&t.ID, &t.Name, &t.Type, &t.Target, &t.Active, &t.Warnings, &t.TotalEvents, &lastEventAt,
	)
	if err != nil {
		return nil, err
	}
	t.LastEventAt = formatLastEvent(lastEventAt)
	return &t, nil
}

func (p *Postgres) UpdateTrap(ctx context.Context, id int64, patch models.TrapPatch) (*models.Trap, error) {
	var setClauses []string
	var args []any
	argIdx := 1

	if patch.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *patch.Name)
		argIdx++
	}
	if patch.Type != nil {
		setClauses = append(setClauses, fmt.Sprintf("type = $%d", argIdx))
		args = append(args, *patch.Type)
		argIdx++
	}
	if patch.Target != nil {
		setClauses = append(setClauses, fmt.Sprintf("target = $%d", argIdx))
		args = append(args, *patch.Target)
		argIdx++
	}
	if patch.Active != nil {
		setClauses = append(setClauses, fmt.Sprintf("active = $%d", argIdx))
		args = append(args, *patch.Active)
		argIdx++
	}

	if len(setClauses) == 0 {
		return p.GetTrap(ctx, id)
	}

	args = append(args, id)
	query := fmt.Sprintf(`
		UPDATE traps
		SET %s
		WHERE id = $%d
		RETURNING id, name, type, target, active, warnings, total_events, last_event_at
	`, strings.Join(setClauses, ", "), argIdx)

	var t models.Trap
	var lastEventAt sql.NullTime
	err := p.db.QueryRowContext(ctx, query, args...).Scan(
		&t.ID, &t.Name, &t.Type, &t.Target, &t.Active, &t.Warnings, &t.TotalEvents, &lastEventAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.LastEventAt = formatLastEvent(lastEventAt)
	return &t, nil
}

func (p *Postgres) DeleteTrap(ctx context.Context, id int64) error {
	res, err := p.db.ExecContext(ctx, "DELETE FROM traps WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------- events ----------------

func (p *Postgres) ListEvents(ctx context.Context, trapID int64) ([]models.Event, error) {
	var exists bool
	err := p.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM traps WHERE id = $1)", trapID).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}

	rows, err := p.db.QueryContext(ctx, `
		SELECT id, type, source, time, detail
		FROM events
		WHERE trap_id = $1
		ORDER BY id ASC
	`, trapID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var e models.Event
		if err := rows.Scan(&e.ID, &e.Type, &e.Source, &e.Time, &e.Detail); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if events == nil {
		events = []models.Event{}
	}
	return events, nil
}

// ---------------- stats ----------------

func (p *Postgres) GetStats(ctx context.Context) (*models.Stats, error) {
	var activeTraps, warnings24h int
	err := p.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN active THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(warnings), 0)
		FROM traps
	`).Scan(&activeTraps, &warnings24h)
	if err != nil {
		return nil, err
	}
	return &models.Stats{
		ActiveTraps: activeTraps,
		Warnings24h: warnings24h,
		ActiveTasks: 1,
	}, nil
}

// ---------------- users ----------------

func (p *Postgres) CreateUser(ctx context.Context, u *models.User) (*models.User, error) {
	var out models.User
	err := p.db.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, username, email, password_hash, created_at
	`, u.Username, u.Email, u.PasswordHash).Scan(
		&out.ID, &out.Username, &out.Email, &out.PasswordHash, &out.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return &out, nil
}

func (p *Postgres) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var u models.User
	err := p.db.QueryRowContext(ctx, `
		SELECT id, username, email, password_hash, created_at
		FROM users
		WHERE LOWER(username) = LOWER($1)
	`, username).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (p *Postgres) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	var u models.User
	err := p.db.QueryRowContext(ctx, `
		SELECT id, username, email, password_hash, created_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func formatLastEvent(nt sql.NullTime) string {
	if !nt.Valid {
		return "—"
	}
	return nt.Time.Format("2006-01-02 15:04:05")
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return true
	}
	if strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "duplicate key value") {
		return true
	}
	return false
}
