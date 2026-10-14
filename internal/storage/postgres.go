package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
	// всё в одной транзакции: при ошибке сида не останется полузаполненной БД
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin init tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // после Commit это no-op

	if _, err := tx.ExecContext(ctx, migrations.SchemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	var empty bool
	if err := tx.QueryRowContext(ctx,
		"SELECT NOT EXISTS (SELECT 1 FROM users) AND NOT EXISTS (SELECT 1 FROM traps)",
	).Scan(&empty); err != nil {
		return fmt.Errorf("check tables are empty: %w", err)
	}
	if empty {
		if _, err := tx.ExecContext(ctx, migrations.SeedSQL); err != nil {
			return fmt.Errorf("apply seed: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit init tx: %w", err)
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

const trapCols = `
	t.id, t.name, t.class, t.bind, t.port, t.ports, t.params, t.token, t.key_id, t.pub_key, t.priv_key, t.enabled, t.last_seen, t.created_at,
	(SELECT COUNT(*) FROM events e WHERE e.trap_id = t.id),
	(SELECT COUNT(*) FROM events e WHERE e.trap_id = t.id AND e.event_type IN ('auth','scan','token')),
	(SELECT MAX(ts) FROM events e WHERE e.trap_id = t.id)`

func scanTrap(row interface{ Scan(...any) error }) (*models.Trap, error) {
	var t models.Trap
	var params []byte
	var lastSeen sql.NullTime
	var lastTS sql.NullFloat64
	if err := row.Scan(
		&t.ID, &t.Name, &t.Class, &t.Bind, &t.Port, &t.Ports, &params, &t.Token,
		&t.KeyID, &t.PubKey, &t.PrivKey, &t.Enabled,
		&lastSeen, &t.CreatedAt, &t.TotalEvents, &t.Warnings, &lastTS,
	); err != nil {
		return nil, err
	}
	t.Params = json.RawMessage(params)
	if lastSeen.Valid {
		ls := lastSeen.Time
		t.LastSeen = &ls
	}
	t.Status = trapStatus(t.LastSeen, time.Now())
	if lastTS.Valid {
		t.LastEventAt = formatTS(lastTS.Float64)
	} else {
		t.LastEventAt = "—"
	}
	return &t, nil
}

func (p *Postgres) ListTraps(ctx context.Context) ([]models.Trap, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT `+trapCols+` FROM traps t ORDER BY t.id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	traps := []models.Trap{}
	for rows.Next() {
		t, err := scanTrap(rows)
		if err != nil {
			return nil, err
		}
		traps = append(traps, *t)
	}
	return traps, rows.Err()
}

func (p *Postgres) GetTrap(ctx context.Context, id int64) (*models.Trap, error) {
	row := p.db.QueryRowContext(ctx, `SELECT `+trapCols+` FROM traps t WHERE t.id = $1`, id)
	t, err := scanTrap(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (p *Postgres) GetTrapByToken(ctx context.Context, token string) (*models.Trap, error) {
	row := p.db.QueryRowContext(ctx, `SELECT `+trapCols+` FROM traps t WHERE t.token = $1`, token)
	t, err := scanTrap(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (p *Postgres) GetTrapByKeyID(ctx context.Context, keyID string) (*models.Trap, error) {
	if keyID == "" {
		return nil, ErrNotFound
	}
	row := p.db.QueryRowContext(ctx, `SELECT `+trapCols+` FROM traps t WHERE t.key_id = $1`, keyID)
	t, err := scanTrap(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (p *Postgres) CreateTrap(ctx context.Context, in models.TrapCreate, token string) (*models.Trap, error) {
	params := in.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	var id int64
	err := p.db.QueryRowContext(ctx, `
		INSERT INTO traps (name, class, bind, port, ports, params, token, key_id, pub_key, priv_key, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, in.Name, in.Class, in.Bind, in.Port, in.Ports, []byte(params), token, in.KeyID, in.PubKey, in.PrivKey, in.Enabled).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return p.GetTrap(ctx, id)
}

func (p *Postgres) UpdateTrap(ctx context.Context, id int64, patch models.TrapPatch) (*models.Trap, error) {
	var set []string
	var args []any
	i := 1
	add := func(col string, val any) {
		set = append(set, fmt.Sprintf("%s = $%d", col, i))
		args = append(args, val)
		i++
	}
	if patch.Name != nil {
		add("name", *patch.Name)
	}
	if patch.Bind != nil {
		add("bind", *patch.Bind)
	}
	if patch.Port != nil {
		add("port", *patch.Port)
	}
	if patch.Ports != nil {
		add("ports", *patch.Ports)
	}
	if patch.Params != nil {
		add("params", []byte(*patch.Params))
	}
	if patch.KeyID != nil {
		add("key_id", *patch.KeyID)
	}
	if patch.PubKey != nil {
		add("pub_key", *patch.PubKey)
	}
	if patch.PrivKey != nil {
		add("priv_key", *patch.PrivKey)
	}
	if patch.Enabled != nil {
		add("enabled", *patch.Enabled)
	}
	if len(set) == 0 {
		return p.GetTrap(ctx, id)
	}
	args = append(args, id)
	res, err := p.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE traps SET %s WHERE id = $%d", strings.Join(set, ", "), i), args...)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return p.GetTrap(ctx, id)
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

func (p *Postgres) InsertEvent(ctx context.Context, trapID int64, in models.IngestEvent) (*models.Event, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Обновление last_seen заодно подтверждает, что ловушка существует.
	res, err := tx.ExecContext(ctx, "UPDATE traps SET last_seen = NOW() WHERE id = $1", trapID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}

	ts := in.TS
	if ts == 0 {
		ts = float64(time.Now().Unix())
	}
	data := in.Data
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}
	var id int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO events (trap_id, event_type, proto, src_ip, src_port, dst_port, session, username, password, data, ts)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id
	`, trapID, in.EventType, nz(in.Proto, "tcp"), in.SrcIP, in.SrcPort, in.DstPort, in.Session,
		in.Username, in.Password, []byte(data), ts).Scan(&id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &models.Event{
		ID: id, TrapID: trapID, Type: in.EventType, Proto: nz(in.Proto, "tcp"),
		Source: in.SrcIP, SrcPort: in.SrcPort, DstPort: in.DstPort, Session: in.Session,
		Username: in.Username, Password: in.Password, Data: data, TS: ts, Time: formatTS(ts),
	}, nil
}

func (p *Postgres) TouchTrap(ctx context.Context, token string) error {
	res, err := p.db.ExecContext(ctx, "UPDATE traps SET last_seen = NOW() WHERE token = $1", token)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) ListFilterEvents(ctx context.Context, f models.EventFilter) ([]models.Event, error) {
	if f.TrapID != 0 {
		var exists bool
		if err := p.db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM traps WHERE id = $1)", f.TrapID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrNotFound
		}
	}

	sb := strings.Builder{}
	sb.WriteString(`
		SELECT e.id, e.trap_id, t.name, t.class, e.event_type, e.proto, e.src_ip, e.src_port, e.dst_port,
		       e.session, e.username, e.password, e.data, e.ts
		FROM events e JOIN traps t ON t.id = e.trap_id WHERE 1=1`)
	var args []any
	i := 1
	cond := func(clause string, val any) {
		sb.WriteString(fmt.Sprintf(" AND %s$%d", clause, i))
		args = append(args, val)
		i++
	}
	if f.TrapID != 0 {
		cond("e.trap_id = ", f.TrapID)
	}
	if f.EventType != "" {
		cond("e.event_type = ", f.EventType)
	}
	if f.SrcIP != "" {
		cond("e.src_ip = ", f.SrcIP)
	}
	if f.SinceTS > 0 {
		cond("e.ts >= ", f.SinceTS)
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	sb.WriteString(fmt.Sprintf(" ORDER BY e.ts DESC LIMIT $%d", i))
	args = append(args, limit)

	rows, err := p.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []models.Event{}
	for rows.Next() {
		var e models.Event
		var data []byte
		var user, pass sql.NullString
		if err := rows.Scan(&e.ID, &e.TrapID, &e.TrapName, &e.Class, &e.Type, &e.Proto,
			&e.Source, &e.SrcPort, &e.DstPort, &e.Session, &user, &pass, &data, &e.TS); err != nil {
			return nil, err
		}
		if user.Valid {
			e.Username = &user.String
		}
		if pass.Valid {
			e.Password = &pass.String
		}
		e.Data = json.RawMessage(data)
		e.Time = formatTS(e.TS)
		events = append(events, e)
	}
	return events, rows.Err()
}

// ---------------- stats ----------------

func (p *Postgres) GetStats(ctx context.Context) (*models.Stats, error) {
	var s models.Stats
	err := p.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN enabled THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN last_seen >= NOW() - INTERVAL '120 seconds' THEN 1 ELSE 0 END), 0)
		FROM traps
	`).Scan(&s.ActiveTraps, &s.OnlineTraps)
	if err != nil {
		return nil, err
	}
	since := float64(time.Now().Add(-24 * time.Hour).Unix())
	err = p.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN event_type IN ('auth','scan','token') AND ts >= $1 THEN 1 ELSE 0 END), 0)
		FROM events
	`, since).Scan(&s.TotalEvents, &s.Warnings24h)
	if err != nil {
		return nil, err
	}
	return &s, nil
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
		FROM users WHERE LOWER(username) = LOWER($1)
	`, username).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.CreatedAt)
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
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return true
	}
	return strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "duplicate key value")
}
