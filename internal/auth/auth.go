package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SessionTTL — время жизни сессии; совпадает со сроком жизни cookie.
const SessionTTL = 7 * 24 * time.Hour

// MaxPasswordBytes — bcrypt не принимает пароли длиннее 72 байт.
const MaxPasswordBytes = 72

type session struct {
	userID  int64
	expires time.Time
}

// Manager holds opaque session tokens in memory.
// Replace with JWT or a session store (Redis) later.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]session // token -> session
	now      func() time.Time
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]session), now: time.Now}
}

func (m *Manager) CreateToken(userID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)

	now := m.now()
	m.mu.Lock()
	// заодно вычищаем протухшие сессии, чтобы map не рос бесконечно
	for k, s := range m.sessions {
		if now.After(s.expires) {
			delete(m.sessions, k)
		}
	}
	m.sessions[tok] = session{userID: userID, expires: now.Add(SessionTTL)}
	m.mu.Unlock()
	return tok, nil
}

func (m *Manager) UserID(token string) (int64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[token]
	if !ok || m.now().After(s.expires) {
		return 0, false
	}
	return s.userID, true
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

// dummyHash используется, когда пользователь не найден: проверка пароля
// всё равно выполняется, и по времени ответа нельзя узнать, существует ли логин.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

// SimulatePasswordCheck тратит столько же времени, сколько настоящая проверка пароля.
func (m *Manager) SimulatePasswordCheck(pw string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
}
