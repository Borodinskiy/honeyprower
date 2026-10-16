package storage

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"

	"golang.org/x/crypto/bcrypt"

	"honeyprower/internal/models"
)

// Seed populates demo data for the in-memory store (admin/admin + example
// trap definitions). The Postgres store seeds itself from migrations/002_seed.sql.
func Seed(s *Memory) {
	ctx := context.Background()

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("seed: bcrypt: %v", err)
		return
	}
	if _, err := s.CreateUser(ctx, &models.User{
		Username:     "admin",
		Email:        "admin@example.com",
		PasswordHash: string(hash),
	}); err != nil {
		log.Printf("seed: user: %v", err)
	} else {
		log.Printf("Using InMemory database. Administrator auth data: %s:%s", "admin", "admin")
	}

	demo := []struct {
		in    models.TrapCreate
		token string
	}{
		{models.TrapCreate{Name: "SSH баннер (демо, low)", Class: "banner", Bind: "0.0.0.0", Port: 2222,
			Params: json.RawMessage(`{"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n","close_after_input":true}`), Enabled: true}, "demo-ssh-banner-token"},
		{models.TrapCreate{Name: "FTP vsftpd (демо, medium)", Class: "dialog", Bind: "0.0.0.0", Port: 2121,
			Params: json.RawMessage(`{"greeting":"220 (vsFTPd 3.0.5)\r\n","decoder":"line","rules":[{"match":"^USER\\s+(.*)$","response":"331 Please specify the password.\r\n","capture":"username"},{"match":"^PASS\\s?(.*)$","response":"530 Login incorrect.\r\n","capture":"password"},{"match":"^QUIT","response":"221 Goodbye.\r\n","close":true}]}`), Enabled: true}, "demo-ftp-token"},
		{models.TrapCreate{Name: "IEC-104 Substation (демо, ics)", Class: "iec104", Bind: "0.0.0.0", Port: 2404,
			Params: json.RawMessage(`{}`), Enabled: true}, "demo-iec104-token"},
		{models.TrapCreate{Name: "Modbus SCADA Gateway (демо, ics)", Class: "scada", Bind: "0.0.0.0", Port: 502,
			Params: json.RawMessage(`{}`), Enabled: true}, "demo-scada-token"},
		{models.TrapCreate{Name: "High-Interaction Shell (демо, high)", Class: "high_interaction", Bind: "0.0.0.0", Port: 2224,
			Params: json.RawMessage(`{}`), Enabled: true}, "demo-high-shell-token"},
	}
	for _, d := range demo {
		d.in.KeyID, d.in.PubKey, d.in.PrivKey = DemoTrapKeys(d.token)
		if _, err := s.CreateTrap(ctx, d.in, d.token); err != nil {
			log.Printf("seed: trap: %v", err)
		}
	}
}

// DemoTrapKeys — постоянные ключи демо-ловушки, выведенные из её токена. Их
// открытые ключи лежат в deploy/agent-configs, поэтому демо-агенты из
// docker-compose шифруют события так, что центр их принимает. Те же значения
// записаны в migrations/002_seed.sql. Настоящие ловушки получают случайные ключи.
func DemoTrapKeys(token string) (keyID, pubHex, privHex string) {
	sha := sha256.Sum256([]byte(token))
	keyID = hex.EncodeToString(sha[:8])
	seed := sha256.Sum256([]byte("honeyforge-demo-key:" + token))
	priv, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		panic(err) // X25519 принимает любые 32 байта
	}
	return keyID, hex.EncodeToString(priv.PublicKey().Bytes()), hex.EncodeToString(priv.Bytes())
}
