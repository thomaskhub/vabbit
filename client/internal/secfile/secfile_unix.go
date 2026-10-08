//go:build !windows

package secfile

import (
	"fmt"
	"os"
)

// Check refuses a file that other users can read.
func Check(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users (mode %o); run chmod 600 on it", path, fi.Mode().Perm())
	}
	return nil
}

// MkdirAll creates dir with mode 0700.
func MkdirAll(dir string, _ Scope) error { return os.MkdirAll(dir, 0o700) }

// Protect sets mode 0600 on f.
func Protect(f *os.File, _ Scope) error { return f.Chmod(0o600) }
