// Package secret шифрует учётные данные хостов (SSH-пароли и ключи) перед
// записью в базу: утечка дампа БД без ключа не раскрывает доступ к серверам.
//
// Шифр — AES-256-GCM. Ключ берётся из HF_SECRET_KEY, иначе из файла ключа
// (по умолчанию data/secret.key), который создаётся при первом запуске.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// prefix помечает формат шифротекста, чтобы потом можно было сменить алгоритм.
const prefix = "v1:"

// ErrDecrypt — шифротекст повреждён или зашифрован другим ключом.
var ErrDecrypt = errors.New("secret: cannot decrypt (wrong key or corrupted data)")

// Box шифрует и расшифровывает короткие строки одним ключом.
type Box struct {
	aead cipher.AEAD
}

// New создаёт Box из 32-байтного ключа.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal шифрует строку. Пустая строка остаётся пустой: «секрета нет».
func (b *Box) Seal(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.StdEncoding.EncodeToString(out), nil
}

// Open расшифровывает результат Seal. Пустая строка — пустой секрет.
func (b *Box) Open(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	raw, ok := strings.CutPrefix(sealed, prefix)
	if !ok {
		return "", ErrDecrypt
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", ErrDecrypt
	}
	n := b.aead.NonceSize()
	if len(data) < n+b.aead.Overhead() {
		return "", ErrDecrypt
	}
	plain, err := b.aead.Open(nil, data[:n], data[n:], nil)
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plain), nil
}

// ParseKey превращает значение HF_SECRET_KEY в ключ: 64 hex-символа или
// base64 от 32 байт берутся как есть, любая другая строка (не короче 16
// символов) — как парольная фраза через SHA-256.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	if len(s) < 16 {
		return nil, errors.New("secret: key is too short (need 64 hex chars, base64 of 32 bytes or a passphrase of 16+ chars)")
	}
	sum := sha256.Sum256([]byte(s))
	return sum[:], nil
}

// LoadOrCreateKeyFile читает ключ из файла (hex). Если файла нет — создаёт
// новый случайный ключ с правами 0600 (каталог — 0700).
func LoadOrCreateKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, perr := hex.DecodeString(strings.TrimSpace(string(data)))
		if perr != nil || len(key) != 32 {
			return nil, fmt.Errorf("secret: key file %s is malformed (want 64 hex chars)", path)
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("secret: read key file: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secret: create key dir: %w", err)
	}
	// O_EXCL: если два процесса стартуют одновременно, второй не перетрёт ключ первого.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return LoadOrCreateKeyFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("secret: create key file: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("secret: write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("secret: write key file: %w", err)
	}
	return key, nil
}
