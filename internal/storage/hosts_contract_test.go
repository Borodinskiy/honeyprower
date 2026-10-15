package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"honeyprower/internal/models"
)

// testHostsContract проверяет хосты и привязку ловушек одинаково для любой
// реализации Storage: память и Postgres должны вести себя одинаково.
func testHostsContract(t *testing.T, s Storage) {
	ctx := context.Background()
	str := func(v string) *string { return &v }
	id := func(v int64) *int64 { return &v }

	web, err := s.CreateHost(ctx, models.Host{
		Name: "web-01", Address: "10.0.0.5", SSHPort: 22, Username: "root", AuthType: "password",
		PasswordEnc: "v1:enc-pass", SudoPasswordEnc: "v1:enc-sudo", UseSudo: true,
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if web.ID == 0 || web.CreatedAt.IsZero() || web.DeployedAt != nil {
		t.Fatalf("unexpected created host: %+v", web)
	}
	if web.PasswordEnc != "v1:enc-pass" || web.SudoPasswordEnc != "v1:enc-sudo" || !web.UseSudo {
		t.Fatalf("secrets/flags not stored: %+v", web)
	}

	// Тот же сервер (регистр адреса и пробелы не важны) — конфликт; другой SSH-порт — другой хост.
	if _, err := s.CreateHost(ctx, models.Host{Name: "dup", Address: "10.0.0.5", SSHPort: 22, Username: "u", AuthType: "password"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate host: err = %v, want ErrAlreadyExists", err)
	}
	db, err := s.CreateHost(ctx, models.Host{Name: "DB", Address: "Db.Internal", SSHPort: 2200, Username: "admin", AuthType: "key", PrivateKeyEnc: "v1:enc-key"})
	if err != nil {
		t.Fatalf("CreateHost db: %v", err)
	}
	if _, err := s.CreateHost(ctx, models.Host{Name: "dup2", Address: "db.internal", SSHPort: 2200, Username: "u", AuthType: "password"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("address must be case-insensitive: err = %v", err)
	}

	hosts, err := s.ListHosts(ctx)
	if err != nil || len(hosts) != 2 || hosts[0].ID != web.ID || hosts[1].ID != db.ID {
		t.Fatalf("ListHosts = %+v, %v", hosts, err)
	}
	if _, err := s.GetHost(ctx, 987654); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetHost missing: %v", err)
	}

	// Частичное обновление не трогает остальные поля.
	upd, err := s.UpdateHost(ctx, web.ID, models.HostPatch{Name: str("web-01a"), PasswordEnc: str("v1:new")})
	if err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}
	if upd.Name != "web-01a" || upd.PasswordEnc != "v1:new" || upd.SudoPasswordEnc != "v1:enc-sudo" || upd.Address != "10.0.0.5" {
		t.Fatalf("partial update wrong: %+v", upd)
	}
	if same, err := s.UpdateHost(ctx, web.ID, models.HostPatch{}); err != nil || same.Name != "web-01a" {
		t.Fatalf("empty patch: %+v, %v", same, err)
	}
	if _, err := s.UpdateHost(ctx, web.ID, models.HostPatch{Address: str("DB.internal"), SSHPort: func() *int { p := 2200; return &p }()}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("moving onto another host's address: err = %v", err)
	}
	if got, _ := s.GetHost(ctx, web.ID); got.Address != "10.0.0.5" {
		t.Fatalf("failed update must not change the host: %+v", got)
	}
	if _, err := s.UpdateHost(ctx, 987654, models.HostPatch{Name: str("x")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateHost missing: %v", err)
	}

	// Отметка о развёртывании.
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	if err := s.SetHostDeployed(ctx, web.ID, &at, "hash-1"); err != nil {
		t.Fatalf("SetHostDeployed: %v", err)
	}
	got, _ := s.GetHost(ctx, web.ID)
	if got.DeployedAt == nil || !got.DeployedAt.Equal(at) || got.DeployedHash != "hash-1" {
		t.Fatalf("deployed mark: %+v", got)
	}
	if err := s.SetHostDeployed(ctx, web.ID, nil, "ignored"); err != nil {
		t.Fatalf("clear deployed: %v", err)
	}
	if got, _ := s.GetHost(ctx, web.ID); got.DeployedAt != nil || got.DeployedHash != "" {
		t.Fatalf("deployed mark not cleared: %+v", got)
	}
	if err := s.SetHostDeployed(ctx, 987654, &at, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetHostDeployed missing: %v", err)
	}

	// Ловушки и хосты.
	mk := func(name string, host *int64, token string) *models.Trap {
		t.Helper()
		tr, err := s.CreateTrap(ctx, models.TrapCreate{HostID: host, Name: name, Class: "banner", Bind: "0.0.0.0", Port: 2222,
			Params: json.RawMessage(`{}`), Enabled: true}, token)
		if err != nil {
			t.Fatalf("CreateTrap %s: %v", name, err)
		}
		return tr
	}
	onWeb := mk("on-web", id(web.ID), "tok-host-1")
	loose := mk("loose", nil, "tok-host-2")
	if onWeb.HostID == nil || *onWeb.HostID != web.ID || loose.HostID != nil {
		t.Fatalf("hostId not stored: %+v / %+v", onWeb.HostID, loose.HostID)
	}
	if _, err := s.CreateTrap(ctx, models.TrapCreate{HostID: id(987654), Name: "x", Class: "banner", Port: 1}, "tok-host-3"); !errors.Is(err, ErrNoSuchHost) {
		t.Fatalf("trap on unknown host: err = %v, want ErrNoSuchHost", err)
	}

	// Перенос, отвязка, «поле не передано».
	moved, err := s.UpdateTrap(ctx, loose.ID, models.TrapPatch{HostID: models.OptionalID{Set: true, ID: id(db.ID)}})
	if err != nil || moved.HostID == nil || *moved.HostID != db.ID {
		t.Fatalf("move trap: %+v, %v", moved, err)
	}
	renamed, err := s.UpdateTrap(ctx, loose.ID, models.TrapPatch{Name: str("renamed")})
	if err != nil || renamed.HostID == nil || *renamed.HostID != db.ID {
		t.Fatalf("absent hostId must keep the host: %+v, %v", renamed, err)
	}
	if _, err := s.UpdateTrap(ctx, loose.ID, models.TrapPatch{HostID: models.OptionalID{Set: true, ID: id(987654)}}); !errors.Is(err, ErrNoSuchHost) {
		t.Fatalf("move to unknown host: err = %v", err)
	}
	if tr, _ := s.GetTrap(ctx, loose.ID); tr.HostID == nil || *tr.HostID != db.ID {
		t.Fatalf("failed move must keep the old host: %+v", tr.HostID)
	}
	unassigned, err := s.UpdateTrap(ctx, loose.ID, models.TrapPatch{HostID: models.OptionalID{Set: true}})
	if err != nil || unassigned.HostID != nil {
		t.Fatalf("unassign: %+v, %v", unassigned, err)
	}

	// Удаление хоста отвязывает его ловушки, но не трогает их события.
	if _, err := s.InsertEvent(ctx, onWeb.ID, models.IngestEvent{EventType: "connect", SrcIP: "198.51.100.1"}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
	if err := s.DeleteHost(ctx, web.ID); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	if _, err := s.GetHost(ctx, web.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("host still there: %v", err)
	}
	orphan, err := s.GetTrap(ctx, onWeb.ID)
	if err != nil || orphan.HostID != nil || orphan.TotalEvents != 1 {
		t.Fatalf("trap after host delete: %+v, %v", orphan, err)
	}
	if err := s.DeleteHost(ctx, web.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteHost twice: %v", err)
	}
	// Адрес удалённого хоста снова свободен.
	if _, err := s.CreateHost(ctx, models.Host{Name: "web-again", Address: "10.0.0.5", SSHPort: 22, Username: "root", AuthType: "password"}); err != nil {
		t.Fatalf("address of a deleted host must be reusable: %v", err)
	}
}

func TestMemoryHostsContract(t *testing.T) {
	testHostsContract(t, NewInMemory())
}

func TestPostgresHostsContract(t *testing.T) {
	p, _ := newTestPostgres(t)
	testHostsContract(t, p)
}
