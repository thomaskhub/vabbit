// Package adminlogin is the admin's login file, ~/.config/vabbit/admin.json:
// the admin token of every network the admin runs, encrypted with a master
// password. `vabbit deploy` creates the tokens there and fills in each network's
// URL; vabbit reads it for admin commands.
//
// The whole content (names, URLs, tokens) is one sealed blob: Argon2id derives
// a key from the master password, XChaCha20-Poly1305 encrypts and
// authenticates it. Without the password the file reveals nothing and can't be
// altered undetected, so it can be copied to another admin's machine as is.
package adminlogin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"vabbit/internal/secfile"
)

// Network is one network's admin credentials. Server is empty until the
// network has been deployed.
type Network struct {
	Name   string `json:"name"`
	Server string `json:"server,omitempty"`
	Token  string `json:"token"`
}

// Login is the decrypted content of the file.
type Login struct {
	Networks []Network `json:"networks"`
}

// ErrWrongPassword means the master password did not open the file.
var ErrWrongPassword = errors.New("wrong master password")

type sealed struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memoryKiB"`
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

// Argon2id cost: about half a second and 64 MiB per guess.
const (
	kdfTime    = 3
	kdfMemory  = 64 * 1024
	kdfThreads = 4
	ad         = "vabbit-admin-login-v1"
)

// Path is ~/.config/vabbit/admin.json for the invoking user, also under sudo,
// so `sudo vabbit up` can use the admin login.
func Path() (string, error) {
	if os.Geteuid() == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" {
			if u, err := user.Lookup(su); err == nil {
				return filepath.Join(u.HomeDir, ".config", "vabbit", "admin.json"), nil
			}
		}
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vabbit", "admin.json"), nil
}

// Exists reports whether there is a login file at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Load decrypts the login file. It returns os.ErrNotExist if there is none.
func Load(path string, password []byte) (Login, error) {
	if err := secfile.Check(path); err != nil {
		return Login{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Login{}, err
	}
	var s sealed
	if err := json.Unmarshal(b, &s); err != nil || s.Version != 1 {
		return Login{}, fmt.Errorf("%s is not a vabbit admin login (or an older format); move it away and log in again", path)
	}
	aead, err := s.aead(password)
	if err != nil {
		return Login{}, err
	}
	plain, err := aead.Open(nil, s.Nonce, s.Data, []byte(ad))
	if err != nil {
		return Login{}, ErrWrongPassword
	}
	var l Login
	if err := json.Unmarshal(plain, &l); err != nil {
		return Login{}, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// Save encrypts the login with password and writes it atomically (mode 0600,
// directory 0700).
func Save(path string, l Login, password []byte) error {
	if len(password) == 0 {
		return errors.New("empty master password")
	}
	sort.Slice(l.Networks, func(i, j int) bool { return l.Networks[i].Name < l.Networks[j].Name })
	plain, err := json.Marshal(l)
	if err != nil {
		return err
	}
	s := sealed{Version: 1, KDF: "argon2id", Time: kdfTime, Memory: kdfMemory, Threads: kdfThreads,
		Salt: make([]byte, 16), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	if _, err := rand.Read(s.Salt); err != nil {
		return err
	}
	if _, err := rand.Read(s.Nonce); err != nil {
		return err
	}
	aead, err := s.aead(password)
	if err != nil {
		return err
	}
	s.Data = aead.Seal(nil, s.Nonce, plain, []byte(ad))
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := secfile.MkdirAll(filepath.Dir(path), secfile.User); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := secfile.Protect(tmp, secfile.User); err != nil {
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

func (s *sealed) aead(password []byte) (interface {
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
}, error) {
	// Bounds keep a tampered file from asking for absurd amounts of memory.
	if s.KDF != "argon2id" || s.Time < 1 || s.Time > 10 || s.Memory < 8*1024 || s.Memory > 1024*1024 ||
		s.Threads < 1 || len(s.Salt) < 16 || len(s.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("admin login: unsupported encryption parameters")
	}
	return chacha20poly1305.NewX(argon2.IDKey(password, s.Salt, s.Time, s.Memory, s.Threads, chacha20poly1305.KeySize))
}

// Get returns the network called name.
func (l *Login) Get(name string) (Network, bool) {
	for _, n := range l.Networks {
		if n.Name == name {
			return n, true
		}
	}
	return Network{}, false
}

// Set adds or replaces a network by name.
func (l *Login) Set(n Network) {
	for i := range l.Networks {
		if l.Networks[i].Name == n.Name {
			l.Networks[i] = n
			return
		}
	}
	l.Networks = append(l.Networks, n)
}

// Remove drops a network by name.
func (l *Login) Remove(name string) {
	out := l.Networks[:0]
	for _, n := range l.Networks {
		if n.Name != name {
			out = append(out, n)
		}
	}
	l.Networks = out
}

// Select picks the network admin commands act on: the one called name, or
// the only deployed one when name is empty.
func (l *Login) Select(name string) (Network, error) {
	var live []Network
	for _, n := range l.Networks {
		if n.Server != "" {
			live = append(live, n)
		}
	}
	if name != "" {
		n, ok := l.Get(name)
		switch {
		case !ok:
			return Network{}, fmt.Errorf("no admin login for network %q", name)
		case n.Server == "":
			return Network{}, fmt.Errorf("network %q is not deployed yet; run vabbit deploy apply", name)
		}
		return n, nil
	}
	switch len(live) {
	case 0:
		return Network{}, errors.New("no deployed network in the admin login; run vabbit deploy apply or vabbit login")
	case 1:
		return live[0], nil
	}
	names := ""
	for _, n := range live {
		names += " " + n.Name
	}
	return Network{}, fmt.Errorf("the admin login has several networks (%s); pick one with VABBIT_NETWORK=NAME", names[1:])
}

// NewToken returns a new admin token and its SHA-256 (hex), which is what the
// control plane stores.
func NewToken() (token, sha string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = "vba_" + base64.RawURLEncoding.EncodeToString(b)
	return token, Hash(token), nil
}

// Hash is the SHA-256 (hex) of a token.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
