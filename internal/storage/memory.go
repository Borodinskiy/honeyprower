package storage

import (
	"context"
	"sort"
	"strings"
	"sync"

	"honeyprower/internal/models"
)

type Memory struct {
	mu     sync.RWMutex
	nextID int64

	traps  map[int64]*models.Trap
	events map[int64][]models.Event

	users  map[int64]*models.User
	byName map[string]int64 // lower-cased username -> id
}

func NewInMemory() *Memory {
	return &Memory{
		nextID: 1,
		traps:  make(map[int64]*models.Trap),
		events: make(map[int64][]models.Event),
		users:  make(map[int64]*models.User),
		byName: make(map[string]int64),
	}
}

func (m *Memory) nextIDLocked() int64 {
	id := m.nextID
	m.nextID++
	return id
}

// ---------------- traps ----------------

func (m *Memory) ListTraps(_ context.Context) ([]models.Trap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]models.Trap, 0, len(m.traps))
	for _, t := range m.traps {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) GetTrap(_ context.Context, id int64) (*models.Trap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.traps[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *Memory) CreateTrap(_ context.Context, in models.TrapCreate) (*models.Trap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextIDLocked()
	t := &models.Trap{
		ID:          id,
		Name:        in.Name,
		Type:        in.Type,
		Target:      in.Target,
		Active:      in.Active,
		LastEventAt: "—",
	}
	m.traps[id] = t
	m.events[id] = []models.Event{}
	cp := *t
	return &cp, nil
}

func (m *Memory) UpdateTrap(_ context.Context, id int64, p models.TrapPatch) (*models.Trap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.traps[id]
	if !ok {
		return nil, ErrNotFound
	}
	if p.Name != nil {
		t.Name = *p.Name
	}
	if p.Type != nil {
		t.Type = *p.Type
	}
	if p.Target != nil {
		t.Target = *p.Target
	}
	if p.Active != nil {
		t.Active = *p.Active
	}
	cp := *t
	return &cp, nil
}

func (m *Memory) DeleteTrap(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.traps[id]; !ok {
		return ErrNotFound
	}
	delete(m.traps, id)
	delete(m.events, id)
	return nil
}

// ---------------- events ----------------

func (m *Memory) ListEvents(_ context.Context, trapID int64) ([]models.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.traps[trapID]; !ok {
		return nil, ErrNotFound
	}
	src := m.events[trapID]
	out := make([]models.Event, len(src))
	copy(out, src)
	return out, nil
}

// ---------------- stats ----------------

func (m *Memory) GetStats(_ context.Context) (*models.Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := &models.Stats{}
	for _, t := range m.traps {
		if t.Active {
			s.ActiveTraps++
		}
		s.Warnings24h += t.Warnings
	}
	s.ActiveTasks = 1 // placeholder — plug real task engine later
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
