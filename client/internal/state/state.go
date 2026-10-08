// Package state persists device enrollment with tight permissions.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Device is what a machine remembers after enrolling. It contains the
// WireGuard private key and the device token, so it is written 0600.
type Device struct {
	Server      string `json:"server"`
	DeviceID    string `json:"deviceId"`
	DeviceToken string `json:"deviceToken"`
	PrivateKey  string `json:"privateKey"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	NetworkCIDR string `json:"networkCidr"`
	ListenPort  int    `json:"listenPort"`
	Endpoint    string `json:"endpoint,omitempty"`
}

const DefaultDir = "/var/lib/vabbit"

func DevicePath(dir, iface string) string { return filepath.Join(dir, iface+".json") }

// Load reads JSON into v. It returns os.ErrNotExist if the file is missing and
// refuses files that other users can read.
func Load(path string, v any) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users (mode %o); run chmod 600 on it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Save writes v atomically with mode 0600 inside a 0700 directory.
func Save(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
