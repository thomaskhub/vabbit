package adminlogin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vabbit", "admin.json")
	var l Login
	l.Set(Network{Name: "work", Token: "vba_work"})
	l.Set(Network{Name: "home", Server: "https://home.b-cdn.net", Token: "vba_home"})
	if err := Save(path, l, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, leak := range []string{"vba_", "home", "b-cdn"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("%q readable in the file:\n%s", leak, raw)
		}
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	got, err := Load(path, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := got.Get("home"); n.Token != "vba_home" || n.Server != "https://home.b-cdn.net" {
		t.Fatalf("home: %+v", n)
	}
	if _, err := Load(path, []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	// Any change to the ciphertext is detected.
	tampered := bytes.Replace(raw, []byte(`"data": "`), []byte(`"data": "AA`), 1)
	os.WriteFile(path, tampered, 0o600)
	if _, err := Load(path, []byte("correct horse")); err == nil {
		t.Fatal("tampered file accepted")
	}
	if runtime.GOOS != "windows" { // Windows uses ACLs, see internal/secfile
		os.Chmod(path, 0o644)
		if _, err := Load(path, []byte("correct horse")); err == nil {
			t.Fatal("world-readable file accepted")
		}
	}
}

func TestSelect(t *testing.T) {
	var l Login
	if _, err := l.Select(""); err == nil {
		t.Fatal("empty login selected something")
	}
	l.Set(Network{Name: "home", Server: "https://h", Token: "a"})
	l.Set(Network{Name: "lab", Token: "b"}) // not deployed
	if n, err := l.Select(""); err != nil || n.Name != "home" {
		t.Fatalf("%+v %v", n, err)
	}
	if _, err := l.Select("lab"); err == nil {
		t.Fatal("undeployed network selected")
	}
	l.Set(Network{Name: "work", Server: "https://w", Token: "c"})
	if _, err := l.Select(""); err == nil || !strings.Contains(err.Error(), "VABBIT_NETWORK") {
		t.Fatalf("ambiguous: %v", err)
	}
	if n, err := l.Select("work"); err != nil || n.Token != "c" {
		t.Fatalf("%+v %v", n, err)
	}
	l.Remove("work")
	if _, ok := l.Get("work"); ok {
		t.Fatal("not removed")
	}
}

func TestReadMasked(t *testing.T) {
	cases := map[string]string{
		"secret\r":         "secret",
		"sx\x7fecret\r":    "secret",
		"junk\x15secret\r": "secret",
		"päss\r":           "päss",
		"pä\x7fass\r":      "pass",
		"a\x1bb\r":         "ab", // stray control byte ignored
	}
	for in, want := range cases {
		var out bytes.Buffer
		got, err := ReadMasked(strings.NewReader(in), &out)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
		if strings.ContainsAny(out.String(), "secrpäa") {
			t.Errorf("%q: echoed %q", in, out.String())
		}
	}
	var out bytes.Buffer
	ReadMasked(strings.NewReader("päss\r"), &out)
	if strings.Count(out.String(), "*") != 4 {
		t.Errorf("want one * per character, got %q", out.String())
	}
	if _, err := ReadMasked(strings.NewReader("ab\x03"), &out); !errors.Is(err, ErrInterrupted) {
		t.Errorf("ctrl-c: %v", err)
	}
}

func TestNewToken(t *testing.T) {
	tok, sha, err := NewToken()
	if err != nil || !strings.HasPrefix(tok, "vba_") || len(tok) != 47 || Hash(tok) != sha || len(sha) != 64 {
		t.Fatalf("%q %q %v", tok, sha, err)
	}
}
