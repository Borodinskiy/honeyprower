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
	hosts    map[int64]*models.Host
	traps    map[int64]*trapRow
	byToken  map[string]int64
	byKeyID  map[string]int64
	events   map[int64][]models.Event // trapID -> events (oldest first)
	users    map[int64]*models.User
	plugins  map[string]*pluginRow
	byName   map[string]int64 // lower-cased username -> id
	now      func() time.Time
}

func NewInMemory() *Memory {
	return &Memory{
		nextID:  1,
		hosts:   make(map[int64]*models.Host),
		traps:   make(map[int64]*trapRow),
		byToken: make(map[string]int64),
		byKeyID: make(map[string]int64),
		events:  make(map[int64][]models.Event),
		users:   make(map[int64]*models.User),
		plugins: make(map[string]*pluginRow),
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
	if r.def.HostID != nil {
		id := *r.def.HostID
		t.HostID = &id
	}
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

// ---------------- hosts ----------------

func (m *Memory) ListHosts(_ context.Context) ([]models.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]models.Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		out = append(out, copyHost(h))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) GetHost(_ context.Context, id int64) (*models.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := copyHost(h)
	return &cp, nil
}

// hostTakenLocked reports whether another host already uses this address and port.
func (m *Memory) hostTakenLocked(address string, port int, except int64) bool {
	key := hostKey(address, port)
	for id, h := range m.hosts {
		if id != except && hostKey(h.Address, h.SSHPort) == key {
			return true
		}
	}
	return false
}

func (m *Memory) CreateHost(_ context.Context, in models.Host) (*models.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hostTakenLocked(in.Address, in.SSHPort, 0) {
		return nil, ErrAlreadyExists
	}
	h := in
	h.ID = m.nextIDLocked()
	h.CreatedAt = m.now()
	h.DeployedAt = nil
	h.DeployedHash = ""
	m.hosts[h.ID] = &h
	cp := copyHost(&h)
	return &cp, nil
}

func (m *Memory) UpdateHost(_ context.Context, id int64, p models.HostPatch) (*models.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, ErrNotFound
	}
	next := *h
	setIf(&next.Name, p.Name)
	setIf(&next.Address, p.Address)
	setIf(&next.SSHPort, p.SSHPort)
	setIf(&next.Username, p.Username)
	setIf(&next.AuthType, p.AuthType)
	setIf(&next.UseSudo, p.UseSudo)
	setIf(&next.PasswordEnc, p.PasswordEnc)
	setIf(&next.PrivateKeyEnc, p.PrivateKeyEnc)
	setIf(&next.SudoPasswordEnc, p.SudoPasswordEnc)
	if m.hostTakenLocked(next.Address, next.SSHPort, id) {
		return nil, ErrAlreadyExists
	}
	*h = next
	cp := copyHost(h)
	return &cp, nil
}

func (m *Memory) DeleteHost(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[id]; !ok {
		return ErrNotFound
	}
	delete(m.hosts, id)
	for _, r := range m.traps {
		if r.def.HostID != nil && *r.def.HostID == id {
			r.def.HostID = nil
		}
	}
	return nil
}

func (m *Memory) SetHostDeployed(_ context.Context, id int64, at *time.Time, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return ErrNotFound
	}
	if at == nil {
		h.DeployedAt, h.DeployedHash = nil, ""
		return nil
	}
	t := *at
	h.DeployedAt, h.DeployedHash = &t, hash
	return nil
}

func copyHost(h *models.Host) models.Host {
	cp := *h
	if h.DeployedAt != nil {
		t := *h.DeployedAt
		cp.DeployedAt = &t
	}
	return cp
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// hostIDLocked validates a host reference and returns a private copy of it.
func (m *Memory) hostIDLocked(id *int64) (*int64, error) {
	if id == nil {
		return nil, nil
	}
	if _, ok := m.hosts[*id]; !ok {
		return nil, ErrNoSuchHost
	}
	v := *id
	return &v, nil
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

func (m *Memory) GetTrapByKeyID(_ context.Context, keyID string) (*models.Trap, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if keyID == "" || m.byKeyID == nil {
		return nil, ErrNotFound
	}
	id, ok := m.byKeyID[keyID]
	if !ok {
		return nil, ErrNotFound
	}
	r, ok := m.traps[id]
	if !ok {
		return nil, ErrNotFound
	}
	t := m.view(r)
	return &t, nil
}

func (m *Memory) CreateTrap(_ context.Context, in models.TrapCreate, token string) (*models.Trap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hostID, err := m.hostIDLocked(in.HostID)
	if err != nil {
		return nil, err
	}
	if _, taken := m.byToken[token]; taken {
		return nil, ErrAlreadyExists
	}
	id := m.nextIDLocked()
	params := in.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	r := &trapRow{def: models.Trap{
		ID:        id,
		HostID:    hostID,
		Name:      in.Name,
		Class:     in.Class,
		Bind:      in.Bind,
		Port:      in.Port,
		Ports:     in.Ports,
		Params:    params,
		Token:     token,
		KeyID:     in.KeyID,
		PubKey:    in.PubKey,
		PrivKey:   in.PrivKey,
		Enabled:   in.Enabled,
		CreatedAt: m.now(),
	}}
	m.traps[id] = r
	m.byToken[token] = id
	if m.byKeyID == nil {
		m.byKeyID = make(map[string]int64)
	}
	if in.KeyID != "" {
		m.byKeyID[in.KeyID] = id
	}
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
	if p.HostID.Set {
		hostID, err := m.hostIDLocked(p.HostID.ID)
		if err != nil {
			return nil, err
		}
		r.def.HostID = hostID
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
	if p.KeyID != nil {
		if m.byKeyID == nil {
			m.byKeyID = make(map[string]int64)
		}
		if r.def.KeyID != "" {
			delete(m.byKeyID, r.def.KeyID)
		}
		r.def.KeyID = *p.KeyID
		if *p.KeyID != "" {
			m.byKeyID[*p.KeyID] = id
		}
	}
	if p.PubKey != nil {
		r.def.PubKey = *p.PubKey
	}
	if p.PrivKey != nil {
		r.def.PrivKey = *p.PrivKey
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
	if r.def.KeyID != "" && m.byKeyID != nil {
		delete(m.byKeyID, r.def.KeyID)
	}
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

func (m *Memory) AddDemoEvents(_ context.Context, events []DemoEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, de := range events {
		r, ok := m.traps[de.TrapID]
		if !ok {
			return ErrNotFound
		}
		in := de.Event
		m.eventSeq++
		m.events[de.TrapID] = append(m.events[de.TrapID], models.Event{
			ID: m.eventSeq, TrapID: de.TrapID, TrapName: r.def.Name, Class: r.def.Class,
			Type: in.EventType, Proto: in.Proto, Source: in.SrcIP, SrcPort: in.SrcPort, DstPort: in.DstPort,
			Session: in.Session, Username: in.Username, Password: in.Password, Data: in.Data,
			TS: in.TS, Time: formatTS(in.TS),
		})
	}
	return nil
}

func (m *Memory) DeleteDemoEvents(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, evs := range m.events {
		kept := evs[:0]
		for _, e := range evs {
			if strings.HasPrefix(e.Session, DemoSessionPrefix) {
				removed++
			} else {
				kept = append(kept, e)
			}
		}
		m.events[id] = kept
	}
	return removed, nil
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

func (m *Memory) ListFilterEvents(_ context.Context, f models.EventFilter) ([]models.Event, error) {
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

func (m *Memory) GetDashboard(_ context.Context, window, bucket, utcOffset time.Duration) (*models.Dashboard, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d := newDashboard(m.now(), window, bucket, utcOffset)
	var pool []models.Event
	for id, r := range m.traps {
		for _, e := range m.events[id] {
			e.TrapName = r.def.Name // ловушку могли переименовать после события
			pool = append(pool, e)
		}
	}
	dashboardFromEvents(d, pool)
	return d, nil
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

// ---------------- plugins ----------------

type pluginRow struct {
	def     models.Plugin
	archive []byte
}

func (m *Memory) ListPlugins(_ context.Context) ([]models.Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]models.Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		out = append(out, p.def)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetPlugin(_ context.Context, name string) (*models.Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.plugins[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := p.def
	return &cp, nil
}

func (m *Memory) GetPluginArchive(_ context.Context, name string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.plugins[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), p.archive...), nil
}

func (m *Memory) SavePlugin(_ context.Context, p models.Plugin, archive []byte) (*models.Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.UploadedAt = m.now().UTC()
	p.Size = int64(len(archive))
	m.plugins[p.Name] = &pluginRow{def: p, archive: append([]byte(nil), archive...)}
	cp := p
	return &cp, nil
}

func (m *Memory) DeletePlugin(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.plugins[name]; !ok {
		return ErrNotFound
	}
	delete(m.plugins, name)
	return nil
}
