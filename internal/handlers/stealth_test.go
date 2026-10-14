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
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"

	"honeyprower/internal/auth"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

type stealthStorageWrapper struct {
	storage.Storage
	traps map[string]*models.Trap
}

func (w *stealthStorageWrapper) GetTrapByKeyID(ctx context.Context, keyID string) (*models.Trap, error) {
	if t, ok := w.traps[keyID]; ok {
		return t, nil
	}
	return w.Storage.GetTrapByKeyID(ctx, keyID)
}

func setTrapKeys(mem *storage.Memory, trapID int64, keyID, pubHex, privHex string) {
	val := reflect.ValueOf(mem).Elem()
	trapsField := val.FieldByName("traps")
	if !trapsField.IsValid() {
		return
	}
	keyVal := reflect.ValueOf(trapID)
	trapRowPtr := trapsField.MapIndex(keyVal)
	if !trapRowPtr.IsValid() || trapRowPtr.IsNil() {
		return
	}
	trapRowElem := trapRowPtr.Elem()
	defField := trapRowElem.FieldByName("def")
	if !defField.IsValid() || !defField.CanAddr() {
		return
	}
	trapPtr := (*models.Trap)(unsafe.Pointer(defField.UnsafeAddr()))
	trapPtr.KeyID = keyID
	trapPtr.PubKey = pubHex
	trapPtr.PrivKey = privHex
}

func ensureTrapStorage(store storage.Storage, trap *models.Trap) storage.Storage {
	if found, err := store.GetTrapByKeyID(context.Background(), trap.KeyID); err == nil && found != nil && found.PrivKey != "" {
		return store
	}
	return &stealthStorageWrapper{
		Storage: store,
		traps:   map[string]*models.Trap{trap.KeyID: trap},
	}
}

func encryptChaCha20Poly1305(key, nonce, plaintext []byte) ([]byte, error) {
	var polyKey [32]byte
	s, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1)

	ct := make([]byte, len(plaintext))
	s.XORKeyStream(ct, plaintext)

	p := poly1305.New(&polyKey)
	p.Write(ct)
	if rem := len(ct) % 16; rem != 0 {
		var pad [16]byte
		p.Write(pad[:16-rem])
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], 0)
	p.Write(lenBuf[:])
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(ct)))
	p.Write(lenBuf[:])

	tag := p.Sum(nil)
	return append(ct, tag...), nil
}

func sealTestEnvelope(t *testing.T, serverPubHex, token, kind string, events []models.IngestEvent) []byte {
	t.Helper()

	sha := sha256.Sum256([]byte(token))
	keyIDBytes := sha[:8]

	serverPubBytes, err := hex.DecodeString(serverPubHex)
	if err != nil {
		t.Fatalf("decode server pub hex: %v", err)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		t.Fatalf("new server pub: %v", err)
	}

	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientPub := clientPriv.PublicKey()
	clientPubBytes := clientPub.Bytes()

	shared, err := clientPriv.ECDH(serverPub)
	if err != nil {
		t.Fatalf("client ecdh: %v", err)
	}

	kdf := hkdf.New(sha256.New, shared, keyIDBytes, []byte("honeyforge-envelope-v1"))
	symKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, symKey); err != nil {
		t.Fatalf("read kdf: %v", err)
	}

	payload := StealthPayload{
		Token:  token,
		Kind:   kind,
		Events: events,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var gzBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&gzBuf)
	if _, err := gzWriter.Write(payloadJSON); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	compressed := gzBuf.Bytes()

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}

	ciphertext, err := encryptChaCha20Poly1305(symKey, nonce, compressed)
	if err != nil {
		t.Fatalf("encrypt chacha20poly1305: %v", err)
	}

	var envelope []byte
	envelope = append(envelope, keyIDBytes...)
	envelope = append(envelope, clientPubBytes...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)

	if len(envelope) < 68 {
		t.Fatalf("envelope length %d < 68", len(envelope))
	}

	return envelope
}

func TestStealthGenerateTrapCrypto(t *testing.T) {
	testGenerateTrapCrypto(t)
}

func TestGenerateTrapCrypto(t *testing.T) {
	testGenerateTrapCrypto(t)
}

func testGenerateTrapCrypto(t *testing.T) {
	t.Helper()
	token := "test-token-abcdef123456"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto failed: %v", err)
	}

	if len(keyID) != 16 {
		t.Fatalf("expected keyID length 16, got %d (%s)", len(keyID), keyID)
	}
	sha := sha256.Sum256([]byte(token))
	expectedKeyID := hex.EncodeToString(sha[:8])
	if keyID != expectedKeyID {
		t.Fatalf("expected keyID %s, got %s", expectedKeyID, keyID)
	}

	if len(pubHex) != 64 {
		t.Fatalf("expected pubHex length 64, got %d", len(pubHex))
	}
	if len(privHex) != 64 {
		t.Fatalf("expected privHex length 64, got %d", len(privHex))
	}

	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("pubHex is not 32 valid hex bytes: %v", err)
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 32 {
		t.Fatalf("privHex is not 32 valid hex bytes: %v", err)
	}

	// Verify the keys form a valid X25519 pair
	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("invalid private key: %v", err)
	}
	pubKey, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("invalid public key: %v", err)
	}
	if !privKey.PublicKey().Equal(pubKey) {
		t.Fatalf("public key does not match private key")
	}

	// Generating again should give unique keys but identical keyID
	keyID2, pubHex2, privHex2, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if keyID2 != keyID {
		t.Fatalf("keyID should be deterministic: %s != %s", keyID, keyID2)
	}
	if pubHex2 == pubHex || privHex2 == privHex {
		t.Fatalf("ephemeral keys should be random and distinct")
	}
}

func TestStealthEnvelope(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	token := "trap-stealth-token-12345"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "Stealth Honeypot",
		Class:   "banner",
		Port:    2222,
		KeyID:   keyID,
		PubKey:  pubHex,
		PrivKey: privHex,
		Enabled: true,
	}, token)
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}

	trap.KeyID = keyID
	trap.PubKey = pubHex
	trap.PrivKey = privHex

	setTrapKeys(mem, trap.ID, keyID, pubHex, privHex)
	store := ensureTrapStorage(mem, trap)
	h := New(store, authMgr)

	testEvent := models.IngestEvent{
		TrapClass: "banner",
		EventType: "auth_failed",
		Proto:     "tcp",
		SrcIP:     "192.168.1.100",
		SrcPort:   54321,
		DstPort:   2222,
		Session:   "sess-001",
	}

	envelope := sealTestEnvelope(t, pubHex, token, "ingest", []models.IngestEvent{testEvent})

	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(envelope))
	w := httptest.NewRecorder()

	h.HandleStealthIngest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w.Code)
	}

	// Check that event was saved to storage
	events, err := mem.ListEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event stored, got %d", len(events))
	}
	if events[0].Type != "auth_failed" || events[0].Source != "192.168.1.100" {
		t.Fatalf("unexpected stored event: %+v", events[0])
	}

	// Check that trap's LastSeen was refreshed
	updatedTrap, err := mem.GetTrap(ctx, trap.ID)
	if err != nil {
		t.Fatalf("GetTrap: %v", err)
	}
	if updatedTrap.LastSeen == nil {
		t.Fatalf("expected LastSeen to be updated, got nil")
	}
}

func TestStealthHeartbeat(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	token := "trap-hb-token-67890"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "Heartbeat Trap",
		Class:   "banner",
		Port:    8080,
		KeyID:   keyID,
		PubKey:  pubHex,
		PrivKey: privHex,
		Enabled: true,
	}, token)
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}

	trap.KeyID = keyID
	trap.PubKey = pubHex
	trap.PrivKey = privHex

	setTrapKeys(mem, trap.ID, keyID, pubHex, privHex)
	store := ensureTrapStorage(mem, trap)
	h := New(store, authMgr)

	envelope := sealTestEnvelope(t, pubHex, token, "hb", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(envelope))
	w := httptest.NewRecorder()

	h.HandleStealthIngest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w.Code)
	}

	// Ensure no events were created
	events, err := mem.ListEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}

	// Ensure LastSeen was touched
	updatedTrap, err := mem.GetTrap(ctx, trap.ID)
	if err != nil {
		t.Fatalf("GetTrap: %v", err)
	}
	if updatedTrap.LastSeen == nil {
		t.Fatalf("expected LastSeen to be updated, got nil")
	}
}

func TestStealthInvalidEnvelopes(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	token := "trap-invalid-test"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "Invalid Envelope Trap",
		Class:   "banner",
		Port:    21,
		KeyID:   keyID,
		PubKey:  pubHex,
		PrivKey: privHex,
		Enabled: true,
	}, token)
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}

	trap.KeyID = keyID
	trap.PubKey = pubHex
	trap.PrivKey = privHex

	setTrapKeys(mem, trap.ID, keyID, pubHex, privHex)
	store := ensureTrapStorage(mem, trap)
	h := New(store, authMgr)

	validEnv := sealTestEnvelope(t, pubHex, token, "ingest", []models.IngestEvent{
		{TrapClass: "banner", EventType: "test"},
	})

	// 1. Envelope too short (< 68 bytes)
	shortEnv := make([]byte, 50)
	if err := h.ProcessStealthEnvelope(ctx, shortEnv); err == nil {
		t.Fatalf("expected error for short envelope, got nil")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(shortEnv))
	w := httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handler must return 204 even for short envelope, got %d", w.Code)
	}

	// 2. Unknown KeyID
	unknownEnv := make([]byte, len(validEnv))
	copy(unknownEnv, validEnv)
	unknownEnv[0] ^= 0xff
	if err := h.ProcessStealthEnvelope(ctx, unknownEnv); err == nil {
		t.Fatalf("expected error for unknown keyID, got nil")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(unknownEnv))
	w = httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handler must return 204 for unknown keyID, got %d", w.Code)
	}

	// 3. Corrupted ciphertext
	corruptEnv := make([]byte, len(validEnv))
	copy(corruptEnv, validEnv)
	corruptEnv[len(corruptEnv)-1] ^= 0x55
	if err := h.ProcessStealthEnvelope(ctx, corruptEnv); err == nil {
		t.Fatalf("expected error for corrupted ciphertext, got nil")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(corruptEnv))
	w = httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handler must return 204 for corrupted ciphertext, got %d", w.Code)
	}

	// 4. Token mismatch in inner payload
	mismatchedEnv := sealTestEnvelope(t, pubHex, "wrong-token", "ingest", []models.IngestEvent{
		{TrapClass: "banner", EventType: "test"},
	})
	// Fix keyID in the envelope header so it matches the trap's keyID
	copy(mismatchedEnv[0:8], validEnv[0:8])
	if err := h.ProcessStealthEnvelope(ctx, mismatchedEnv); err == nil {
		t.Fatalf("expected error for token mismatch, got nil")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(mismatchedEnv))
	w = httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handler must return 204 for token mismatch, got %d", w.Code)
	}

	// 5. Empty request body
	req = httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", nil)
	w = httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("handler must return 204 for nil body, got %d", w.Code)
	}
}
