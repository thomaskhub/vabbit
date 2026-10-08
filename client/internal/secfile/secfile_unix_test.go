//go:build !windows

package secfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectAndCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vabbit")
	if err := MkdirAll(dir, Machine); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(dir, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Protect(f, Machine); err != nil {
		t.Fatal(err)
	}
	if err := Check(f.Name()); err != nil {
		t.Fatal(err)
	}
	os.Chmod(f.Name(), 0o644)
	if err := Check(f.Name()); err == nil {
		t.Fatal("world-readable file accepted")
	}
}
