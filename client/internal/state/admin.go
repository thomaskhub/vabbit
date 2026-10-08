package state

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Admin is the admin login: the control plane URL and the admin token.
type Admin struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

// adminFile is admin.json on disk. With a master password the token is only
// stored encrypted (Argon2id + XChaCha20-Poly1305); the server URL stays
// readable and is bound to the ciphertext as associated data.
type adminFile struct {
	Server    string        `json:"server"`
	Token     string        `json:"token,omitempty"`
	Encrypted *sealedSecret `json:"encrypted,omitempty"`
}

type sealedSecret struct {
	KDF     string `json:"kdf"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memoryKiB"`
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

// Argon2id cost: about half a second and 64 MiB per guess on a laptop.
const (
	kdfTime    = 3
	kdfMemory  = 64 * 1024
	kdfThreads = 4
)

// ErrWrongPassword means the master password did not decrypt the admin login.
var ErrWrongPassword = errors.New("wrong master password")

// SaveAdmin writes the admin login. With a non-empty password the token is
// encrypted; with an empty one it is stored in plain text (mode 0600).
func SaveAdmin(path string, a Admin, password []byte) error {
	f := adminFile{Server: a.Server}
	if len(password) == 0 {
		f.Token = a.Token
		return Save(path, f)
	}
	s := &sealedSecret{KDF: "argon2id", Time: kdfTime, Memory: kdfMemory, Threads: kdfThreads,
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
	s.Data = aead.Seal(nil, s.Nonce, []byte(a.Token), []byte(a.Server))
	f.Encrypted = s
	return Save(path, f)
}

// LoadAdmin reads the admin login. password is called only when the token is
// encrypted. It returns os.ErrNotExist when there is no login.
func LoadAdmin(path string, password func() ([]byte, error)) (Admin, error) {
	var f adminFile
	if err := Load(path, &f); err != nil {
		return Admin{}, err
	}
	if f.Encrypted == nil {
		return Admin{Server: f.Server, Token: f.Token}, nil
	}
	pw, err := password()
	if err != nil {
		return Admin{}, err
	}
	aead, err := f.Encrypted.aead(pw)
	if err != nil {
		return Admin{}, err
	}
	tok, err := aead.Open(nil, f.Encrypted.Nonce, f.Encrypted.Data, []byte(f.Server))
	if err != nil {
		return Admin{}, ErrWrongPassword
	}
	return Admin{Server: f.Server, Token: string(tok)}, nil
}

// AdminEncrypted reports whether the stored login needs the master password.
func AdminEncrypted(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var f adminFile
	return json.Unmarshal(b, &f) == nil && f.Encrypted != nil
}

func (s *sealedSecret) aead(password []byte) (interface {
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
}, error) {
	// Bounds keep a tampered file from asking for absurd amounts of memory.
	if s.KDF != "argon2id" || s.Time < 1 || s.Time > 10 || s.Memory < 8*1024 || s.Memory > 1024*1024 ||
		s.Threads < 1 || len(s.Salt) < 16 || len(s.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("admin login: unsupported encryption parameters")
	}
	key := argon2.IDKey(password, s.Salt, s.Time, s.Memory, s.Threads, chacha20poly1305.KeySize)
	return chacha20poly1305.NewX(key)
}
