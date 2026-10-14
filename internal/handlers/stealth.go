package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"

	"honeyprower/internal/models"
)

// ErrReplayDetected is returned when an envelope has already been processed recently.
var ErrReplayDetected = errors.New("replay detected")

var (
	replayCachesMu sync.RWMutex
	replayCaches   = make(map[*Handlers]*ReplayCache)
)

// ReplayCache tracks recently observed (KeyID + EphemeralPK + Nonce) combinations.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	maxSize int
	ttl     time.Duration
}

// NewReplayCache creates an anti-replay cache with default or custom bounds.
func NewReplayCache(maxSize int, ttl time.Duration) *ReplayCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &ReplayCache{
		entries: make(map[string]time.Time),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// CheckAndRecord returns ErrReplayDetected if the key was already observed within ttl,
// or records the key with the current timestamp and returns nil.
func (c *ReplayCache) CheckAndRecord(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Check if already seen
	if ts, exists := c.entries[key]; exists {
		if now.Sub(ts) <= c.ttl {
			return ErrReplayDetected
		}
	}

	// Size-bounded eviction: remove expired entries first
	if len(c.entries) >= c.maxSize {
		for k, ts := range c.entries {
			if now.Sub(ts) > c.ttl {
				delete(c.entries, k)
			}
		}
		// If still at or over maxSize, remove the oldest entry
		if len(c.entries) >= c.maxSize {
			var oldestKey string
			var oldestTime time.Time
			for k, ts := range c.entries {
				if oldestKey == "" || ts.Before(oldestTime) {
					oldestKey = k
					oldestTime = ts
				}
			}
			if oldestKey != "" {
				delete(c.entries, oldestKey)
			}
		}
	}

	c.entries[key] = now
	return nil
}

// Reset clears all entries in the cache.
func (c *ReplayCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]time.Time)
}

// getReplayCache retrieves or initializes the ReplayCache for this Handlers instance.
func (h *Handlers) getReplayCache() *ReplayCache {
	if h == nil {
		return NewReplayCache(10000, 24*time.Hour)
	}
	replayCachesMu.RLock()
	c, ok := replayCaches[h]
	replayCachesMu.RUnlock()
	if ok {
		return c
	}

	replayCachesMu.Lock()
	defer replayCachesMu.Unlock()
	if c, ok = replayCaches[h]; ok {
		return c
	}
	c = NewReplayCache(10000, 24*time.Hour)
	replayCaches[h] = c
	return c
}

// ResetReplayCache clears the anti-replay cache for this Handlers instance.
func (h *Handlers) ResetReplayCache() {
	if h != nil {
		h.getReplayCache().Reset()
	}
}

// StealthPayload represents the decrypted and decompressed payload structure
// sent by stealth agents in a binary envelope.
type StealthPayload struct {
	Token  string               `json:"t"`
	Kind   string               `json:"k"`
	Events []models.IngestEvent `json:"e"`
}


// GenerateTrapCrypto generates KeyID and an X25519 keypair for a given trap token.
// keyID is the first 8 bytes of SHA-256 of the token (16 lowercase hex characters).
// pubHex and privHex are 64 lowercase hex characters (32 bytes each).
func GenerateTrapCrypto(token string) (keyID, pubHex, privHex string, err error) {
	sha := sha256.Sum256([]byte(token))
	keyID = hex.EncodeToString(sha[:8])

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate x25519 key: %w", err)
	}

	pubKey := privKey.PublicKey()
	pubHex = hex.EncodeToString(pubKey.Bytes())
	privHex = hex.EncodeToString(privKey.Bytes())
	return keyID, pubHex, privHex, nil
}

// decryptChaCha20Poly1305 decrypts ciphertext with 16-byte Poly1305 tag according to RFC 8439.
func decryptChaCha20Poly1305(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	if len(nonce) != 12 {
		return nil, errors.New("chacha20poly1305: bad nonce length")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("chacha20poly1305: ciphertext too short")
	}

	tag := ciphertext[len(ciphertext)-16:]
	ct := ciphertext[:len(ciphertext)-16]

	var polyKey [32]byte
	s, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1)

	p := poly1305.New(&polyKey)
	p.Write(ct)
	if rem := len(ct) % 16; rem != 0 {
		var pad [16]byte
		p.Write(pad[:16-rem])
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], 0) // len(additionalData) == 0
	p.Write(lenBuf[:])
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(ct)))
	p.Write(lenBuf[:])

	if !p.Verify(tag) {
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}

	plaintext := make([]byte, len(ct))
	s.XORKeyStream(plaintext, ct)
	return plaintext, nil
}

// ProcessStealthEnvelope decrypts and handles an incoming binary stealth envelope.
// Binary format:
// [KeyID: 8B] || [Ephem_PK: 32B] || [Nonce: 12B] || [Ciphertext + Tag: N + 16B]
// Total minimum envelope length is 68 bytes.
func (h *Handlers) ProcessStealthEnvelope(ctx context.Context, raw []byte) error {
	if h.Store == nil {
		return errors.New("storage is nil")
	}
	if len(raw) < 68 {
		return errors.New("stealth envelope too short: minimum length is 68 bytes")
	}

	// Anti-replay protection: verify (KeyID + EphemeralPK + Nonce) was not previously seen
	replayKey := hex.EncodeToString(raw[0:52])
	if err := h.getReplayCache().CheckAndRecord(replayKey); err != nil {
		return err
	}

	keyID := hex.EncodeToString(raw[0:8])

	trap, err := h.Store.GetTrapByKeyID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("lookup trap by key id failed: %w", err)
	}
	if trap == nil {
		return errors.New("trap not found")
	}

	privBytes, err := hex.DecodeString(trap.PrivKey)
	if err != nil {
		return fmt.Errorf("decode trap private key hex failed: %w", err)
	}
	serverPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return fmt.Errorf("parse server private key failed: %w", err)
	}

	clientPub, err := ecdh.X25519().NewPublicKey(raw[8:40])
	if err != nil {
		return fmt.Errorf("parse client public key failed: %w", err)
	}

	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return fmt.Errorf("compute ecdh shared secret failed: %w", err)
	}

	kdf := hkdf.New(sha256.New, shared, raw[0:8], []byte("honeyforge-envelope-v1"))
	symKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, symKey); err != nil {
		return fmt.Errorf("hkdf key derivation failed: %w", err)
	}

	compressed, err := decryptChaCha20Poly1305(symKey, raw[40:52], raw[52:])
	if err != nil {
		return fmt.Errorf("decrypt envelope failed: %w", err)
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("gzip reader failed: %w", err)
	}
	defer gz.Close()

	plaintext, err := io.ReadAll(gz)
	if err != nil {
		return fmt.Errorf("gzip decompress failed: %w", err)
	}

	var payload StealthPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return fmt.Errorf("unmarshal stealth payload failed: %w", err)
	}

	if payload.Token != trap.Token {
		return errors.New("token mismatch")
	}

	if payload.Kind == "hb" || len(payload.Events) == 0 {
		return h.Store.TouchTrap(ctx, trap.Token)
	}

	for _, ev := range payload.Events {
		if _, err := h.Store.InsertEvent(ctx, trap.ID, ev); err != nil {
			return fmt.Errorf("insert event failed: %w", err)
		}
	}

	return nil
}

// HandleStealthIngest receives binary stealth envelopes and always returns 204 No Content,
// even if the payload is malformed or invalid, to prevent leaking trap presence to scanners.
func (h *Handlers) HandleStealthIngest(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err == nil {
			_ = h.ProcessStealthEnvelope(r.Context(), body)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
