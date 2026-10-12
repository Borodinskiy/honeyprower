package storage

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"honeyprower/internal/models"
)

type trapRow struct {
	def      models.Trap
	lastSeen *time.Time
}

type Memory struct {
	mu       sync.RWMutex
	nextID   int64
	eventSeq int64
	traps    map[int64]*trapRow
	byToken  map[string]int64
	events   map[int64][]models.Event // trapID -> events (oldest first)
	users    map[int64]*models.User
	byName   map[string]int64 // lower-cased username -> id
	now      func() time.Time
}

func NewInMemory() *Memory {
	return &Memory{
		nextID:  1,
		traps:   make(map[int64]*trapRow),
		byToken: make(map[string]int64),
		events:  make(map[int64][]models.Event),
		users:   make(map[int64]*models.User),
		byName:  make(map[string]int64),
		now:     time.Now,
	}
}

func (m *Memory) nextIDLocked() int64 {
	id := m.nextID
	m.nextID++
	return id
}

// view builds a read copy with derived fields filled from the trap's events.
func (m *Memory) view(r *trapRow) models.Trap {
	t := r.def
	t.LastSeen = r.lastSeen
	t.Status = trapStatus(r.lastSeen, m.now())
	evs := m.events[t.ID]
	t.TotalEvents = len(evs)
	warnings := 0
	for _, e := range evs {
		if isWarning(e.Type) {
			warnings++
		}
	}
	t.Warnings = warnings
	if n := len(evs); n > 0 {
		t.LastEventAt = formatTS(evs[n-1].TS)
	} else {
		t.LastEventAt = "—"
	}
	if len(t.Params) == 0 {
		t.Params = json.RawMessage("{}")
	}
	return t
}

// ---------------- traps ----------------

func (m *Memory) ListTraps(_ context.Context) ([]models.Trap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]models.Trap, 0, len(m.traps))
	for _, r := range m.traps {
		out = append(out, m.view(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) GetTrap(_ context.Context, id int64) (*models.Trap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.traps[id]
	if !ok {
		return nil, ErrNotFound
	}
	t := m.view(r)
	return &t, nil
}

func (m *Memory) GetTrapByToken(_ context.Context, token string) (*models.Trap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byToken[token]
	if !ok {
		return nil, ErrNotFound
	}
	t := m.view(m.traps[id])
	return &t, nil
}

func (m *Memory) CreateTrap(_ context.Context, in models.TrapCreate, token string) (*models.Trap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextIDLocked()
	params := in.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	r := &trapRow{def: models.Trap{
		ID:        id,
		Name:      in.Name,
		Class:     in.Class,
		Bind:      in.Bind,
		Port:      in.Port,
		Ports:     in.Ports,
		Params:    params,
		Token:     token,
		Enabled:   in.Enabled,
		CreatedAt: m.now(),
	}}
	m.traps[id] = r
	m.byToken[token] = id
	m.events[id] = []models.Event{}
	t := m.view(r)
	return &t, nil
}

func (m *Memory) UpdateTrap(_ context.Context, id int64, p models.TrapPatch) (*models.Trap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.traps[id]
	if !ok {
		return nil, ErrNotFound
	}
	if p.Name != nil {
		r.def.Name = *p.Name
	}
	if p.Bind != nil {
		r.def.Bind = *p.Bind
	}
	if p.Port != nil {
		r.def.Port = *p.Port
	}
	if p.Ports != nil {
		r.def.Ports = *p.Ports
	}
	if p.Params != nil {
		r.def.Params = *p.Params
	}
	if p.Enabled != nil {
		r.def.Enabled = *p.Enabled
	}
	t := m.view(r)
	return &t, nil
}

func (m *Memory) DeleteTrap(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.traps[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.byToken, r.def.Token)
	delete(m.traps, id)
	delete(m.events, id)
	return nil
}

// ---------------- events ----------------

func (m *Memory) InsertEvent(_ context.Context, trapID int64, in models.IngestEvent) (*models.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.traps[trapID]
	if !ok {
		return nil, ErrNotFound
	}
	m.eventSeq++
	ts := in.TS
	if ts == 0 {
		ts = float64(m.now().Unix())
	}
	ev := models.Event{
		ID:       m.eventSeq,
		TrapID:   trapID,
		TrapName: r.def.Name,
		Class:    r.def.Class,
		Type:     in.EventType,
		Proto:    in.Proto,
		Source:   in.SrcIP,
		SrcPort:  in.SrcPort,
		DstPort:  in.DstPort,
		Session:  in.Session,
		Username: in.Username,
		Password: in.Password,
		Data:     in.Data,
		TS:       ts,
		Time:     formatTS(ts),
	}
	m.events[trapID] = append(m.events[trapID], ev)
	now := m.now()
	r.lastSeen = &now
	return &ev, nil
}

func (m *Memory) TouchTrap(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byToken[token]
	if !ok {
		return ErrNotFound
	}
	now := m.now()
	m.traps[id].lastSeen = &now
	return nil
}

func (m *Memory) ListEvents(_ context.Context, f models.EventFilter) ([]models.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pool []models.Event
	if f.TrapID != 0 {
		if _, ok := m.traps[f.TrapID]; !ok {
			return nil, ErrNotFound
		}
		pool = m.events[f.TrapID]
	} else {
		for _, evs := range m.events {
			pool = append(pool, evs...)
		}
	}

	out := make([]models.Event, 0, len(pool))
	for _, e := range pool {
		if f.EventType != "" && e.Type != f.EventType {
			continue
		}
		if f.SrcIP != "" && e.Source != f.SrcIP {
			continue
		}
		if f.SinceTS > 0 && e.TS < f.SinceTS {
			continue
		}
		out = append(out, e)
	}
	// Новые сверху.
	sort.Slice(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---------------- stats ----------------

func (m *Memory) GetStats(_ context.Context) (*models.Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := &models.Stats{}
	now := m.now()
	since := float64(now.Add(-24 * time.Hour).Unix())
	for id, r := range m.traps {
		if r.def.Enabled {
			s.ActiveTraps++
		}
		if trapStatus(r.lastSeen, now) == "online" {
			s.OnlineTraps++
		}
		for _, e := range m.events[id] {
			s.TotalEvents++
			if isWarning(e.Type) && e.TS >= since {
				s.Warnings24h++
			}
		}
	}
	return s, nil
}

// ---------------- users ----------------

func (m *Memory) CreateUser(_ context.Context, u *models.User) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := strings.ToLower(u.Username)
	if _, exists := m.byName[key]; exists {
		return nil, ErrAlreadyExists
	}
	id := m.nextIDLocked()
	u.ID = id
	if u.CreatedAt.IsZero() {
		u.CreatedAt = m.now()
	}
	cp := *u
	m.users[id] = &cp
	m.byName[key] = id
	return &cp, nil
}

func (m *Memory) GetUserByUsername(_ context.Context, username string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byName[strings.ToLower(username)]
	if !ok {
		return nil, ErrNotFound
	}
	u := m.users[id]
	cp := *u
	return &cp, nil
}

func (m *Memory) GetUserByID(_ context.Context, id int64) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

// formatTS renders a unix timestamp (seconds, possibly fractional) for the UI.
func formatTS(ts float64) string {
	if ts == 0 {
		return "—"
	}
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC().Format("2006-01-02 15:04:05")
}
