package storage

import (
	"context"
	"log"

	"golang.org/x/crypto/bcrypt"

	"honeyprower/internal/models"
)

// Seed populates demo data (admin/admin + 3 traps with events).
// Delete this call in main.go when you wire a real DB.
// TODO: реализовать реальную базу данных
func Seed(s *Memory) {
	ctx := context.Background()

	// demo user: admin / admin
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

	type seedTrap struct {
		in       models.TrapCreate
		warnings int
		total    int
		last     string
		events   []models.Event
	}

	seeds := []seedTrap{
		{
			in:       models.TrapCreate{Name: "SSH Honeypot", Type: "SSH", Target: "192.168.1.10:22", Active: true},
			warnings: 142, total: 1420, last: "2 мин назад",
			events: []models.Event{
				{Type: "connection", Source: "10.0.0.42", Time: "2024-01-15 12:34:56", Detail: "SSH-2.0-OpenSSH_8.2"},
				{Type: "auth", Source: "192.168.1.50", Time: "2024-01-15 11:20:11", Detail: "user=root pass=admin"},
				{Type: "scan", Source: "203.0.113.5", Time: "2024-01-15 09:15:33", Detail: "nmap -sV"},
			},
		},
		{
			in:       models.TrapCreate{Name: "Web Trap", Type: "Web", Target: "http://10.0.0.5/", Active: true},
			warnings: 87, total: 870, last: "15 мин назад",
			events: []models.Event{
				{Type: "connection", Source: "198.51.100.7", Time: "2024-01-15 14:22:01", Detail: "GET /admin.php"},
			},
		},
		{
			in:       models.TrapCreate{Name: "FTP Trap", Type: "FTP", Target: "192.168.1.12:21", Active: false},
			warnings: 0, total: 0, last: "—",
			events: []models.Event{},
		},
	}

	for _, sd := range seeds {
		created, err := s.CreateTrap(ctx, sd.in)
		if err != nil {
			log.Printf("seed: trap: %v", err)
			continue
		}
		s.mu.Lock()
		t := s.traps[created.ID]
		t.Warnings = sd.warnings
		t.TotalEvents = sd.total
		t.LastEventAt = sd.last
		evs := make([]models.Event, len(sd.events))
		for i, e := range sd.events {
			e.ID = s.nextIDLocked()
			evs[i] = e
		}
		s.events[created.ID] = evs
		s.mu.Unlock()
	}
}
