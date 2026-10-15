package storage

import (
	"context"
	"reflect"
	"testing"
	"time"

	"honeyprower/internal/models"
)

// testDashboardContract проверяет агрегаты дашборда одинаково для памяти и Postgres.
func testDashboardContract(t *testing.T, s Storage) {
	ctx := context.Background()
	str := func(v string) *string { return &v }

	ssh, err := s.CreateTrap(ctx, models.TrapCreate{Name: "ssh", Class: "banner", Port: 2222, Enabled: true}, "tok-dash-1")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	web, err := s.CreateTrap(ctx, models.TrapCreate{Name: "web", Class: "http", Port: 8080, Enabled: true}, "tok-dash-2")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}

	now := float64(time.Now().Unix())
	insert := func(trap int64, typ, ip string, ago time.Duration, user, pass *string) {
		t.Helper()
		_, err := s.InsertEvent(ctx, trap, models.IngestEvent{
			EventType: typ, SrcIP: ip, Username: user, Password: pass, TS: now - ago.Seconds(),
		})
		if err != nil {
			t.Fatalf("InsertEvent: %v", err)
		}
	}
	insert(ssh.ID, "auth", "1.1.1.1", time.Minute, str("root"), str("123456"))
	insert(ssh.ID, "auth", "1.1.1.1", 2*time.Minute, str("root"), str("admin"))
	insert(ssh.ID, "connect", "1.1.1.1", 3*time.Minute, nil, nil)
	insert(web.ID, "request", "2.2.2.2", 3*time.Hour, nil, nil)
	insert(web.ID, "scan", "1.1.1.1", 5*time.Hour, nil, nil)
	insert(web.ID, "auth", "", 6*time.Hour, str("admin"), str("123456"))
	insert(ssh.ID, "auth", "3.3.3.3", 30*time.Hour, str("old"), str("old")) // вне окна 24ч

	d, err := s.GetDashboard(ctx, 24*time.Hour, time.Hour, 0)
	if err != nil {
		t.Fatalf("GetDashboard: %v", err)
	}
	if len(d.Timeline) != 24 || d.BucketSeconds != 3600 || d.Until-d.Since != 24*3600 {
		t.Fatalf("window: %d buckets of %ds, %v..%v", len(d.Timeline), d.BucketSeconds, d.Since, d.Until)
	}
	if now < d.Until-3600 || now >= d.Until {
		t.Fatalf("now %v must fall into the last bucket ending at %v", now, d.Until)
	}
	if d.Events != 6 || d.Warnings != 4 || d.UniqueSources != 2 {
		t.Fatalf("totals: events=%d warnings=%d sources=%d", d.Events, d.Warnings, d.UniqueSources)
	}
	sum := 0
	for i, b := range d.Timeline {
		sum += b.Events
		if b.TS != d.Since+float64(i*3600) {
			t.Fatalf("bucket %d starts at %v", i, b.TS)
		}
	}
	if sum != 6 {
		t.Fatalf("timeline sum=%d", sum)
	}

	wantTypes := []models.KeyCount{{Key: "auth", Count: 3}, {Key: "connect", Count: 1}, {Key: "request", Count: 1}, {Key: "scan", Count: 1}}
	if !reflect.DeepEqual(d.ByType, wantTypes) {
		t.Fatalf("ByType = %+v", d.ByType)
	}
	wantTraps := []models.TrapCount{
		{TrapID: ssh.ID, Name: "ssh", Events: 3, Warnings: 2},
		{TrapID: web.ID, Name: "web", Events: 3, Warnings: 2},
	}
	if !reflect.DeepEqual(d.ByTrap, wantTraps) {
		t.Fatalf("ByTrap = %+v", d.ByTrap)
	}
	if len(d.TopSources) != 2 {
		t.Fatalf("TopSources = %+v", d.TopSources)
	}
	top := d.TopSources[0]
	if top.IP != "1.1.1.1" || top.Events != 4 || top.Warnings != 3 || top.Traps != 2 || top.LastTS != now-60 {
		t.Fatalf("top source = %+v", top)
	}
	if !reflect.DeepEqual(d.TopUsernames, []models.KeyCount{{Key: "root", Count: 2}, {Key: "admin", Count: 1}}) {
		t.Fatalf("TopUsernames = %+v", d.TopUsernames)
	}
	if !reflect.DeepEqual(d.TopPasswords, []models.KeyCount{{Key: "123456", Count: 2}, {Key: "admin", Count: 1}}) {
		t.Fatalf("TopPasswords = %+v", d.TopPasswords)
	}

	// Окно 1ч: только события последних минут.
	hour, err := s.GetDashboard(ctx, time.Hour, 5*time.Minute, 0)
	if err != nil {
		t.Fatalf("GetDashboard 1h: %v", err)
	}
	if len(hour.Timeline) != 12 || hour.Events != 3 {
		t.Fatalf("1h window: %d buckets, %d events", len(hour.Timeline), hour.Events)
	}
}

func TestMemoryDashboardContract(t *testing.T) {
	testDashboardContract(t, NewInMemory())
}

func TestPostgresDashboardContract(t *testing.T) {
	p, _ := newTestPostgres(t)
	testDashboardContract(t, p)
}

func TestDashboardEmptyListsAreNotNull(t *testing.T) {
	d, err := NewInMemory().GetDashboard(context.Background(), 24*time.Hour, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.ByType == nil || d.ByTrap == nil || d.TopSources == nil || d.TopUsernames == nil || d.TopPasswords == nil {
		t.Fatalf("empty dashboard has nil lists: %+v", d)
	}
}

func TestDashboardBucketsFollowLocalTime(t *testing.T) {
	now := time.Date(2026, 10, 15, 13, 20, 0, 0, time.UTC) // 16:20 по UTC+3
	d := newDashboard(now, 7*24*time.Hour, 6*time.Hour, 3*time.Hour)
	last := time.Unix(int64(d.Timeline[len(d.Timeline)-1].TS), 0).In(time.FixedZone("UTC+3", 3*3600))
	if last.Hour() != 12 || last.Minute() != 0 || len(d.Timeline) != 28 {
		t.Fatalf("last bucket starts at %v (%d buckets), want 12:00 local", last, len(d.Timeline))
	}
	if float64(now.Unix()) < d.Timeline[27].TS || float64(now.Unix()) >= d.Until {
		t.Fatalf("now is outside the last bucket")
	}
}

// testDemoEventsContract: демо-события видны как обычные, не делают ловушку «на связи»
// и удаляются, не задевая настоящие.
func testDemoEventsContract(t *testing.T, s Storage) {
	ctx := context.Background()
	trap, err := s.CreateTrap(ctx, models.TrapCreate{Name: "demo-target", Class: "ssh", Port: 22, Enabled: true}, "tok-demo-1")
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	now := float64(time.Now().Unix())
	if _, err := s.InsertEvent(ctx, trap.ID, models.IngestEvent{EventType: "connect", SrcIP: "9.9.9.9", Session: "a1b2", TS: now}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
	before, _ := s.GetTrap(ctx, trap.ID)
	user := "root"
	demo := []DemoEvent{
		{TrapID: trap.ID, Event: models.IngestEvent{EventType: "auth", SrcIP: "8.8.8.8", Session: DemoSessionPrefix + "1", Username: &user, TS: now - 60}},
		{TrapID: trap.ID, Event: models.IngestEvent{EventType: "scan", SrcIP: "8.8.8.8", Session: DemoSessionPrefix + "2", Data: []byte(`{"ports":[22]}`), TS: now - 120}},
	}
	if err := s.AddDemoEvents(ctx, demo); err != nil {
		t.Fatalf("AddDemoEvents: %v", err)
	}
	after, _ := s.GetTrap(ctx, trap.ID)
	if before.Status != after.Status || !reflect.DeepEqual(before.LastSeen, after.LastSeen) {
		t.Fatalf("demo events touched last-seen: %v/%v → %v/%v", before.Status, before.LastSeen, after.Status, after.LastSeen)
	}
	evs, err := s.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil || len(evs) != 3 {
		t.Fatalf("events after demo = %d, %v", len(evs), err)
	}

	n, err := s.DeleteDemoEvents(ctx)
	if err != nil || n != 2 {
		t.Fatalf("DeleteDemoEvents = %d, %v", n, err)
	}
	evs, _ = s.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if len(evs) != 1 || evs[0].Session != "a1b2" {
		t.Fatalf("real event must survive: %+v", evs)
	}
}

func TestMemoryDemoEventsContract(t *testing.T) {
	testDemoEventsContract(t, NewInMemory())
}

func TestPostgresDemoEventsContract(t *testing.T) {
	p, _ := newTestPostgres(t)
	testDemoEventsContract(t, p)
}
