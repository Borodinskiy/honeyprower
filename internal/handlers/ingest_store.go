package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"honeyprower/internal/models"
)

// storeEvents сохраняет события ловушки — общий путь /api/ingest и скрытного
// канала. Плохое событие не мешает остальным из того же пакета. Вход с
// учёткой-приманкой из ловушки honeytoken добавляет событие token.
func (h *Handlers) storeEvents(ctx context.Context, trap *models.Trap, events []models.IngestEvent) error {
	var errs []error
	for _, ev := range events {
		ev = sanitizeEvent(ev)
		if ev.EventType == "" {
			continue
		}
		if _, err := h.Store.InsertEvent(ctx, trap.ID, ev); err != nil {
			errs = append(errs, err)
			continue
		}
		if ev.EventType == "auth" {
			if hit := h.honeyCreds.match(ctx, h, ev); hit != nil {
				if _, err := h.Store.InsertEvent(ctx, trap.ID, credentialHit(ev, hit)); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		log.Printf("trap %d: %d event(s) not stored: %v", trap.ID, len(errs), err)
		return err
	}
	return nil
}

// Длины колонок events: длиннее PostgreSQL не примет.
const (
	maxEventType = 50
	maxProto     = 16
	maxSrcIP     = 64
	maxSession   = 64
)

// sanitizeEvent приводит событие к виду, который примет любое хранилище:
// PostgreSQL не хранит символ U+0000 ни в TEXT, ни в JSONB, а он обычен в
// бинарных протоколах (DNS, Modbus) и в выводе своих ловушек.
func sanitizeEvent(ev models.IngestEvent) models.IngestEvent {
	ev.EventType = clip(stripNUL(strings.TrimSpace(ev.EventType)), maxEventType)
	ev.TrapClass = stripNUL(ev.TrapClass)
	ev.Proto = clip(stripNUL(ev.Proto), maxProto)
	ev.SrcIP = clip(stripNUL(ev.SrcIP), maxSrcIP)
	ev.Session = clip(stripNUL(ev.Session), maxSession)
	for _, p := range []**string{&ev.Username, &ev.Password} {
		if *p != nil {
			s := stripNUL(**p)
			*p = &s
		}
	}
	if bytes.Contains(ev.Data, []byte(`\u0000`)) {
		var v any
		if json.Unmarshal(ev.Data, &v) == nil {
			if out, err := json.Marshal(stripNULValue(v)); err == nil {
				ev.Data = out
			}
		}
	}
	return ev
}

func stripNUL(s string) string { return strings.ReplaceAll(s, "\x00", "�") }

func stripNULValue(v any) any {
	switch x := v.(type) {
	case string:
		return stripNUL(x)
	case []any:
		for i := range x {
			x[i] = stripNULValue(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[stripNUL(k)] = stripNULValue(val)
		}
		return out
	}
	return v
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// honeyCred — учётка-приманка из параметров ловушки honeytoken.
type honeyCred struct {
	trapID   int64
	trapName string
	label    string
	username string
	password string
}

// credentialHit — событие token о входе с учёткой-приманкой. Пишется в ту
// ловушку, где был вход: там же адрес и сессия атакующего.
func credentialHit(ev models.IngestEvent, c *honeyCred) models.IngestEvent {
	data, _ := json.Marshal(map[string]any{
		"kind":            "credentials",
		"label":           c.label,
		"honeytoken_trap": c.trapName,
		"honeytoken_id":   c.trapID,
	})
	hit := ev
	hit.EventType = "token"
	hit.Data = data
	return hit
}

// credCache держит учётки-приманки всех ловушек, чтобы не читать их из
// хранилища на каждую попытку входа во время перебора паролей.
type credCache struct {
	mu     sync.Mutex
	creds  []honeyCred
	loaded time.Time
}

const credCacheTTL = 30 * time.Second

func (c *credCache) reset() {
	c.mu.Lock()
	c.loaded = time.Time{}
	c.mu.Unlock()
}

func (c *credCache) match(ctx context.Context, h *Handlers, ev models.IngestEvent) *honeyCred {
	if ev.Password == nil || *ev.Password == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loaded) > credCacheTTL {
		traps, err := h.Store.ListTraps(ctx)
		if err != nil {
			return nil
		}
		c.creds = honeyCredsOf(traps)
		c.loaded = time.Now()
	}
	user := ""
	if ev.Username != nil {
		user = *ev.Username
	}
	for i := range c.creds {
		cr := &c.creds[i]
		if cr.password == *ev.Password && (cr.username == "" || cr.username == user) {
			hit := *cr
			return &hit
		}
	}
	return nil
}

func honeyCredsOf(traps []models.Trap) []honeyCred {
	var out []honeyCred
	for _, t := range traps {
		if t.Class != "honeytoken" || !t.Enabled {
			continue
		}
		var p struct {
			Tokens []struct {
				Kind     string `json:"kind"`
				Label    string `json:"label"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"tokens"`
		}
		if json.Unmarshal(t.Params, &p) != nil {
			continue
		}
		for _, tk := range p.Tokens {
			if tk.Kind == "credentials" && tk.Password != "" {
				out = append(out, honeyCred{trapID: t.ID, trapName: t.Name, label: tk.Label, username: tk.Username, password: tk.Password})
			}
		}
	}
	return out
}
