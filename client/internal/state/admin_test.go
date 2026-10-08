package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	a := Admin{Server: "https://home.b-cdn.net", Token: "vba_secret"}
	if err := SaveAdmin(path, a, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "vba_secret") || !AdminEncrypted(path) {
		t.Fatalf("token stored in clear:\n%s", raw)
	}
	pw := func(p string) func() ([]byte, error) { return func() ([]byte, error) { return []byte(p), nil } }
	if got, err := LoadAdmin(path, pw("correct horse")); err != nil || got != a {
		t.Fatalf("load: %+v %v", got, err)
	}
	if _, err := LoadAdmin(path, pw("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	// The server URL is bound to the ciphertext: pointing the file at another
	// server must not reuse the token there.
	os.WriteFile(path, []byte(strings.Replace(string(raw), "home.b-cdn.net", "evil.example", 1)), 0o600)
	if _, err := LoadAdmin(path, pw("correct horse")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("tampered server accepted: %v", err)
	}
}

func TestAdminPlain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	a := Admin{Server: "https://home.b-cdn.net", Token: "vba_x"}
	if err := SaveAdmin(path, a, nil); err != nil {
		t.Fatal(err)
	}
	asked := false
	got, err := LoadAdmin(path, func() ([]byte, error) { asked = true; return nil, nil })
	if err != nil || got != a || asked || AdminEncrypted(path) {
		t.Fatalf("plain: %+v %v asked=%v", got, err, asked)
	}
}
