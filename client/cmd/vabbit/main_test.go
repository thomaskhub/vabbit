package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseLifetime(t *testing.T) {
	ok := map[string]time.Duration{
		"never": 0, "0": 0, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour,
		"1d12h": 36 * time.Hour, "30m": 30 * time.Minute,
	}
	for in, want := range ok {
		if got, err := parseLifetime(in); err != nil || got != want {
			t.Errorf("%s: got %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "abc", "-1h", "xd", "10s", "d"} {
		if _, err := parseLifetime(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestReadTokenFile(t *testing.T) {
	write := func(content string, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Just the token.
	if s, tok, err := readTokenFile(write("vba_one\n", 0o600), "https://a.b-cdn.net"); err != nil || tok != "vba_one" || s != "https://a.b-cdn.net" {
		t.Fatalf("bare: %q %q %v", s, tok, err)
	}
	// vabbit-deploy format: the newest line per URL wins; the URL fills in --server.
	deployFile := write("home https://home.b-cdn.net vba_old\nwork https://work.b-cdn.net vba_w\nhome https://home.b-cdn.net vba_new\n", 0o600)
	if _, tok, err := readTokenFile(deployFile, "https://home.b-cdn.net/"); err != nil || tok != "vba_new" {
		t.Fatalf("by server: %q %v", tok, err)
	}
	if _, _, err := readTokenFile(deployFile, ""); err == nil {
		t.Fatal("several networks without --server must fail")
	}
	if _, _, err := readTokenFile(deployFile, "https://other.b-cdn.net"); err == nil {
		t.Fatal("unknown server must fail")
	}
	if s, tok, err := readTokenFile(write("home https://home.b-cdn.net vba_x\n", 0o600), ""); err != nil || s != "https://home.b-cdn.net" || tok != "vba_x" {
		t.Fatalf("single line: %q %q %v", s, tok, err)
	}
	// Readable by others: refused.
	if _, _, err := readTokenFile(write("vba_one\n", 0o644), ""); err == nil {
		t.Fatal("world-readable file accepted")
	}
	if _, _, err := readTokenFile(write("hello\n", 0o600), ""); err == nil {
		t.Fatal("file without a token accepted")
	}
}
