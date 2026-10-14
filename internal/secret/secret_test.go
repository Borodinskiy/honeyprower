package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testBox(t *testing.T, fill byte) *Box {
	t.Helper()
	b, err := New(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	b := testBox(t, 1)
	for _, plain := range []string{"x", "p@ss w0rd'\"$", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", "пароль"} {
		sealed, err := b.Seal(plain)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if !strings.HasPrefix(sealed, prefix) {
			t.Fatalf("sealed value lacks prefix: %q", sealed)
		}
		// Короткая строка может случайно встретиться в base64 — проверяем утечку на длинных.
		if len(plain) >= 8 && strings.Contains(sealed, plain) {
			t.Fatalf("sealed value leaks plaintext: %q", sealed)
		}
		got, err := b.Open(sealed)
		if err != nil || got != plain {
			t.Fatalf("Open = %q, %v; want %q", got, err, plain)
		}
	}
}

func TestSealIsRandomized(t *testing.T) {
	b := testBox(t, 1)
	a1, _ := b.Seal("same")
	a2, _ := b.Seal("same")
	if a1 == a2 {
		t.Fatal("two seals of the same secret must differ (random nonce)")
	}
}

func TestEmptyStaysEmpty(t *testing.T) {
	b := testBox(t, 1)
	if s, err := b.Seal(""); s != "" || err != nil {
		t.Fatalf("Seal(\"\") = %q, %v", s, err)
	}
	if s, err := b.Open(""); s != "" || err != nil {
		t.Fatalf("Open(\"\") = %q, %v", s, err)
	}
}

func TestOpenRejectsWrongKeyAndTampering(t *testing.T) {
	b := testBox(t, 1)
	sealed, _ := b.Seal("secret")

	if _, err := testBox(t, 2).Open(sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: err = %v, want ErrDecrypt", err)
	}

	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	raw[len(raw)-1] ^= 0x01
	tampered := prefix + base64.StdEncoding.EncodeToString(raw)

	for name, in := range map[string]string{
		"tampered":   tampered,
		"no prefix":  strings.TrimPrefix(sealed, prefix),
		"bad base64": prefix + "!!!",
		"too short":  prefix + base64.StdEncoding.EncodeToString([]byte("abc")),
		"plaintext":  "secret",
	} {
		if _, err := b.Open(in); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
}

func TestNewRejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("key of %d bytes accepted", n)
		}
	}
}

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, 32)

	k, err := ParseKey(hex.EncodeToString(raw))
	if err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("hex: %x, %v", k, err)
	}
	k, err = ParseKey("  " + base64.StdEncoding.EncodeToString(raw) + "\n")
	if err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("base64: %x, %v", k, err)
	}
	k1, err := ParseKey("correct horse battery staple")
	if err != nil || len(k1) != 32 {
		t.Fatalf("passphrase: %x, %v", k1, err)
	}
	k2, _ := ParseKey("correct horse battery staple")
	if !bytes.Equal(k1, k2) {
		t.Fatal("passphrase must map to a stable key")
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestLoadOrCreateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "secret.key")

	k1, err := LoadOrCreateKeyFile(path)
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %x, %v", k1, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", st.Mode().Perm())
	}

	k2, err := LoadOrCreateKeyFile(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("reload must return the same key: %x vs %x (%v)", k1, k2, err)
	}

	// Секрет, зашифрованный до «перезапуска», расшифровывается после.
	b1, _ := New(k1)
	b2, _ := New(k2)
	sealed, _ := b1.Seal("ssh-pass")
	if got, err := b2.Open(sealed); err != nil || got != "ssh-pass" {
		t.Fatalf("after reload: %q, %v", got, err)
	}
}

func TestLoadKeyFileRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeyFile(path); err == nil {
		t.Fatal("malformed key file must be an error, not silently replaced")
	}
	// Файл не перезаписан: иначе все сохранённые секреты стали бы нечитаемы.
	if data, _ := os.ReadFile(path); string(data) != "not-a-key\n" {
		t.Fatalf("key file was modified: %q", data)
	}
}
