package storage

import (
	"context"
	"encoding/json"
	"log"

	"golang.org/x/crypto/bcrypt"

	"honeyprower/internal/models"
)

// Seed populates demo data for the in-memory store (admin/admin + one example
// trap definition). The Postgres store seeds itself from migrations/002_seed.sql.
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
	}
	for _, d := range demo {
		if _, err := s.CreateTrap(ctx, d.in, d.token); err != nil {
			log.Printf("seed: trap: %v", err)
		}
	}
}
