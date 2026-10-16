package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"honeyprower/internal/models"
)

func TestServeStealthUDPStoresEvents(t *testing.T) {
	h, _, mem := setupTestHandlers()
	token := "udp-trap-token"
	keyID, pub, priv, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatal(err)
	}
	trap, err := mem.CreateTrap(context.Background(), models.TrapCreate{
		Name: "UDP", Class: "banner", Port: 2222, Enabled: true, KeyID: keyID, PubKey: pub, PrivKey: priv,
	}, token)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.ServeStealthUDP(context.Background(), conn) }()

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.Write([]byte("мусор от сканера")) // не мешает следующим датаграммам
	ev := models.IngestEvent{EventType: "auth", SrcIP: "198.51.100.4", Session: "u1"}
	client.Write(sealTestEnvelope(t, pub, token, "ingest", []models.IngestEvent{ev}))

	deadline := time.Now().Add(2 * time.Second)
	for {
		evs, _ := mem.ListFilterEvents(context.Background(), models.EventFilter{TrapID: trap.ID})
		if len(evs) == 1 && evs[0].Source == "198.51.100.4" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("событие из UDP не сохранено: %+v", evs)
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn.Close()
	if err := <-done; err != nil {
		t.Fatalf("закрытие приёмника — не ошибка: %v", err)
	}
}

func TestAgentConfigUDPTransport(t *testing.T) {
	h, _, mem := setupTestHandlers()
	trap, _ := mem.CreateTrap(context.Background(), models.TrapCreate{Name: "T", Class: "banner", Port: 2222, Enabled: true}, "tok")

	get := func() map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/traps/1/config", nil)
		req.Host = "center.example:8080"
		req.SetPathValue("id", "1")
		w := httptest.NewRecorder()
		h.TrapConfig(w, req)
		var cfg map[string]any
		json.Unmarshal(w.Body.Bytes(), &cfg)
		return cfg
	}
	if cfg := get(); cfg["transport"] != "http_nolinger" || cfg["center_udp"] != nil {
		t.Fatalf("по умолчанию HTTP: %v", cfg)
	}

	h.AgentTransport, h.CenterUDP = "udp_burst", ":9099"
	if cfg := get(); cfg["transport"] != "udp_burst" || cfg["center_udp"] != "center.example:9099" {
		t.Fatalf("udp_burst без хоста берёт хост центра: %v", cfg)
	}
	h.CenterUDP = "203.0.113.10:5000"
	if cfg := get(); cfg["center_udp"] != "203.0.113.10:5000" {
		t.Fatalf("явный адрес: %v", cfg)
	}
	_ = trap
}
