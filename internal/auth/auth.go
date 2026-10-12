package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Manager holds opaque session tokens in memory.
// Replace with JWT or a session store (Redis) later.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]int64 // token -> userID
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]int64)}
}

func (m *Manager) CreateToken(userID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	m.mu.Lock()
	m.sessions[tok] = userID
	m.mu.Unlock()
	return tok, nil
}

func (m *Manager) UserID(token string) (int64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.sessions[token]
	return id, ok
}

func (m *Manager) Revoke(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

func (m *Manager) HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func (m *Manager) CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}