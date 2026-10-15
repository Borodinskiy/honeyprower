package storage

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Демо-агенты из docker-compose шифруют события открытыми ключами из своих
// конфигов: SQL-сид и сид памяти должны выдать демо-ловушкам ту же пару.
func TestDemoTrapKeysMatchSeedAndAgentConfigs(t *testing.T) {
	sql, err := os.ReadFile("../../migrations/003_demo_keys.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"demo-ssh-banner-token", "demo-ftp-token", "demo-iec104-token", "demo-scada-token", "demo-high-shell-token"} {
		k, pub, priv := DemoTrapKeys(tok)
		if !strings.Contains(string(sql), "('"+tok+"', '"+k+"', '"+pub+"', '"+priv+"')") {
			t.Errorf("003_demo_keys.sql: нет ключей %s", tok)
		}
	}
	for file, tok := range map[string]string{"ssh.json": "demo-ssh-banner-token", "ftp.json": "demo-ftp-token"} {
		raw, err := os.ReadFile("../../deploy/agent-configs/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Token        string `json:"token"`
			ServerPubKey string `json:"server_pub_key"`
		}
		json.Unmarshal(raw, &cfg)
		_, pub, _ := DemoTrapKeys(tok)
		if cfg.Token != tok || cfg.ServerPubKey != pub {
			t.Errorf("%s: token=%q server_pub_key=%q", file, cfg.Token, cfg.ServerPubKey)
		}
	}

	m := NewInMemory()
	Seed(m)
	tr, err := m.GetTrapByToken(context.Background(), "demo-ftp-token")
	if err != nil {
		t.Fatal(err)
	}
	if k, pub, priv := DemoTrapKeys("demo-ftp-token"); tr.KeyID != k || tr.PubKey != pub || tr.PrivKey != priv {
		t.Fatal("сид памяти выдал демо-ловушке другие ключи")
	}
}
