package demo

import (
	"context"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

func TestHistoryIsMarkedAndInsideWindow(t *testing.T) {
	traps := []models.Trap{
		{ID: 1, Class: "ssh", Port: 22},
		{ID: 2, Class: "http", Port: 80},
		{ID: 3, Class: "scada", Port: 502},
	}
	to := time.Now()
	from := to.Add(-History)
	evs := newGenerator(rand.New(rand.NewSource(1))).history(traps, from, to, 2000)
	if len(evs) < 2000 {
		t.Fatalf("got %d events, want at least 2000", len(evs))
	}

	types := map[string]bool{}
	for _, e := range evs {
		in := e.Event
		if !strings.HasPrefix(in.Session, storage.DemoSessionPrefix) {
			t.Fatalf("event without demo mark: %+v", in)
		}
		// сессия из нескольких шагов может уйти на секунды за правый край — не дальше минуты
		if in.TS < float64(from.Unix()) || in.TS > float64(to.Add(time.Minute).Unix()) {
			t.Fatalf("event outside the window: %v", in.TS)
		}
		ip := net.ParseIP(in.SrcIP)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
			t.Fatalf("bad source ip %q", in.SrcIP)
		}
		if in.EventType == "auth" && (in.Username == nil || in.Password == nil) {
			t.Fatalf("auth without credentials: %+v", in)
		}
		types[in.EventType] = true
	}
	for _, want := range []string{"auth", "scan", "request", "command", "connect"} {
		if !types[want] {
			t.Errorf("no %q events generated", want)
		}
	}
}

func TestRunFillsHistoryAndStops(t *testing.T) {
	s := storage.NewInMemory()
	ctx := context.Background()
	trap, err := s.CreateTrap(ctx, models.TrapCreate{Name: "ssh", Class: "ssh", Port: 22, Enabled: true}, "tok")
	if err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { Run(runCtx, s); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		d, _ := s.GetDashboard(ctx, History, 6*time.Hour, 0)
		if d.Events > 1000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("history not generated, %d events", d.Events)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	if got, _ := s.GetTrap(ctx, trap.ID); got.Status != "never" {
		t.Fatalf("demo traffic must not mark the trap online, status %q", got.Status)
	}
	Clear(ctx, s)
	if d, _ := s.GetDashboard(ctx, History, 6*time.Hour, 0); d.Events != 0 {
		t.Fatalf("Clear left %d events", d.Events)
	}
}
