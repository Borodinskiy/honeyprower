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
	events, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
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
	events, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
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

func TestStealth_AntiReplay(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	token := "trap-antireplay-token-12345"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "AntiReplay Trap",
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
		Session:   "sess-replay-001",
	}

	envelope := sealTestEnvelope(t, pubHex, token, "ingest", []models.IngestEvent{testEvent})

	// First call via HTTP: succeeds and inserts 1 event
	req1 := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(envelope))
	w1 := httptest.NewRecorder()
	h.HandleStealthIngest(w1, req1)
	if w1.Code != http.StatusNoContent {
		t.Fatalf("first call: expected HTTP 204, got %d", w1.Code)
	}

	events, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event after first ingest, got %d", len(events))
	}

	// Second call via HTTP (replay): detects replay, drops processing, returns HTTP 204
	req2 := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(envelope))
	w2 := httptest.NewRecorder()
	h.HandleStealthIngest(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("second call (replay): expected HTTP 204, got %d", w2.Code)
	}

	// Database events must still be exactly 1 (no duplicate inserted)
	eventsAfterReplay, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
	}
	if len(eventsAfterReplay) != 1 {
		t.Fatalf("expected still 1 event after replay, got %d", len(eventsAfterReplay))
	}

	// Direct call to ProcessStealthEnvelope must detect replay
	err = h.ProcessStealthEnvelope(ctx, envelope)
	if err == nil {
		t.Fatalf("expected replay error from ProcessStealthEnvelope, got nil")
	}
	if err.Error() != "replay detected" && !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected 'replay detected' error, got %v", err)
	}
}

func TestStealth_Poly1305Tampering(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	token := "trap-poly-tamper-token"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "Poly Tamper Trap",
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
		SrcIP:     "10.0.0.5",
		DstPort:   2222,
	}
	envelope := sealTestEnvelope(t, pubHex, token, "ingest", []models.IngestEvent{testEvent})

	// Flip 1 bit in Poly1305 tag (last byte)
	tamperedTag := make([]byte, len(envelope))
	copy(tamperedTag, envelope)
	tamperedTag[len(tamperedTag)-1] ^= 0x01

	// Direct call: authentication fails
	if err := h.ProcessStealthEnvelope(ctx, tamperedTag); err == nil {
		t.Fatalf("expected authentication failure for tampered tag, got nil")
	}

	// HTTP ingest: returns 204 No Content
	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(tamperedTag))
	w := httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w.Code)
	}

	// Flip 1 bit in ciphertext payload
	tamperedCipher := make([]byte, len(envelope))
	copy(tamperedCipher, envelope)
	tamperedCipher[55] ^= 0x01

	if err := h.ProcessStealthEnvelope(ctx, tamperedCipher); err == nil {
		t.Fatalf("expected authentication failure for tampered ciphertext, got nil")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(tamperedCipher))
	w2 := httptest.NewRecorder()
	h.HandleStealthIngest(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w2.Code)
	}

	// Verify zero events inserted into storage
	events, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events in storage, got %d", len(events))
	}
}

func TestStealth_UnknownKeyID(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()
	h := New(mem, authMgr)

	token := "unknown-key-test-token"
	_, pubHex, _, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	envelope := sealTestEnvelope(t, pubHex, token, "ingest", []models.IngestEvent{
		{TrapClass: "banner", EventType: "scan"},
	})

	// Direct call should return trap not found
	if err := h.ProcessStealthEnvelope(ctx, envelope); err == nil {
		t.Fatalf("expected error for unknown key ID, got nil")
	}

	// HTTP call must return 204 No Content
	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(envelope))
	w := httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty response body, got %d bytes", w.Body.Len())
	}

	events, err := mem.ListFilterEvents(ctx, models.EventFilter{})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events in storage, got %d", len(events))
	}
}

func TestStealth_CorruptedGzip(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	token := "corrupt-gzip-token"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(token)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "Corrupted Gzip Trap",
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

	// Build envelope with valid crypto but corrupted (non-gzip) plaintext
	sha := sha256.Sum256([]byte(token))
	keyIDBytes := sha[:8]

	serverPubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}

	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	clientPubBytes := clientPriv.PublicKey().Bytes()

	shared, err := clientPriv.ECDH(serverPub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	kdf := hkdf.New(sha256.New, shared, keyIDBytes, []byte("honeyforge-envelope-v1"))
	symKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, symKey); err != nil {
		t.Fatalf("read kdf: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}

	// Non-gzip data encrypted with valid ChaCha20-Poly1305
	notGzipData := []byte("This is plain text and definitely not valid gzip stream data!")
	ciphertext, err := encryptChaCha20Poly1305(symKey, nonce, notGzipData)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	var envelope []byte
	envelope = append(envelope, keyIDBytes...)
	envelope = append(envelope, clientPubBytes...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)

	// Direct call: decompression fails
	err = h.ProcessStealthEnvelope(ctx, envelope)
	if err == nil {
		t.Fatalf("expected error for corrupted gzip, got nil")
	}

	// HTTP call: returns 204 No Content
	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(envelope))
	w := httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w.Code)
	}

	events, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events in storage, got %d", len(events))
	}
}

func TestStealth_TokenMismatch(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()

	realToken := "trap-real-token-12345"
	keyID, pubHex, privHex, err := GenerateTrapCrypto(realToken)
	if err != nil {
		t.Fatalf("GenerateTrapCrypto: %v", err)
	}

	trap, err := mem.CreateTrap(ctx, models.TrapCreate{
		Name:    "Token Mismatch Trap",
		Class:   "banner",
		Port:    2222,
		KeyID:   keyID,
		PubKey:  pubHex,
		PrivKey: privHex,
		Enabled: true,
	}, realToken)
	if err != nil {
		t.Fatalf("CreateTrap: %v", err)
	}
	trap.KeyID = keyID
	trap.PubKey = pubHex
	trap.PrivKey = privHex
	setTrapKeys(mem, trap.ID, keyID, pubHex, privHex)
	store := ensureTrapStorage(mem, trap)
	h := New(store, authMgr)

	// Create envelope with mismatched token inside payload
	mismatchedEnv := sealTestEnvelope(t, pubHex, "attacker-spoofed-token", "ingest", []models.IngestEvent{
		{TrapClass: "banner", EventType: "auth_failed"},
	})
	// Overwrite envelope's KeyID with the real trap's KeyID so trap lookup succeeds
	realKeyIDBytes, err := hex.DecodeString(keyID)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	copy(mismatchedEnv[0:8], realKeyIDBytes)

	// Direct call should return token mismatch error
	err = h.ProcessStealthEnvelope(ctx, mismatchedEnv)
	if err == nil {
		t.Fatalf("expected error for token mismatch, got nil")
	}

	// HTTP call must return 204 No Content
	req := httptest.NewRequest(http.MethodPost, "/api/stealth/ingest", bytes.NewReader(mismatchedEnv))
	w := httptest.NewRecorder()
	h.HandleStealthIngest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", w.Code)
	}

	events, err := mem.ListFilterEvents(ctx, models.EventFilter{TrapID: trap.ID})
	if err != nil {
		t.Fatalf("ListFilterEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events in storage, got %d", len(events))
	}
}
