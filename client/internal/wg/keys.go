// Package wg runs an embedded userspace WireGuard device (wireguard-go) whose
// UDP socket is shared with a STUN client for NAT traversal.
package wg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateKey returns a new base64 WireGuard private key and its public key.
func GenerateKey() (priv, pub string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	// WireGuard clamping (RFC 7748).
	b[0] &= 248
	b[31] = (b[31] & 127) | 64
	return encodeKeyPair(b[:])
}

// PublicKey derives the public key from a base64 private key.
func PublicKey(priv string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid private key")
	}
	_, pub, err := encodeKeyPair(b)
	return pub, err
}

func encodeKeyPair(b []byte) (string, string, error) {
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(b), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ValidKey reports whether s is exactly a canonical base64 32-byte key.
// (Go's decoder skips newlines, so decoding alone is not enough.)
func ValidKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s
}

// keyHex converts a base64 key to the hex form the UAPI protocol uses.
func keyHex(s string) (string, error) {
	if !ValidKey(s) {
		return "", fmt.Errorf("invalid key")
	}
	b, _ := base64.StdEncoding.DecodeString(s)
	return hex.EncodeToString(b), nil
}

func keyB64(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid key")
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
