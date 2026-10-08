// Package wg generates keys, validates control plane data and renders and
// applies WireGuard configuration.
package wg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"edgeguard/internal/api"
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

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// Interface is the validated desired state of the WireGuard interface.
type Interface struct {
	PrivateKey string
	ListenPort int
	Address    netip.Prefix
	Peers      []api.Peer
}

// FromSync validates everything the control plane sent before it is applied.
// The control plane is trusted to introduce peers, but never to route traffic
// outside the network CIDR pinned at enrollment, and nothing it sends can
// inject extra lines into the WireGuard config.
func FromSync(s api.SyncResponse, pinnedCIDR, privateKey string, listenPort int) (Interface, error) {
	network, err := netip.ParsePrefix(pinnedCIDR)
	if err != nil {
		return Interface{}, fmt.Errorf("bad pinned CIDR: %w", err)
	}
	if s.Network.CIDR != pinnedCIDR {
		return Interface{}, fmt.Errorf("server network CIDR %q differs from enrolled %q", s.Network.CIDR, pinnedCIDR)
	}
	addr, err := netip.ParsePrefix(s.Address)
	if err != nil || !addr.Addr().Is4() || addr.Bits() != network.Bits() || !network.Contains(addr.Addr()) {
		return Interface{}, fmt.Errorf("server sent invalid address %q", s.Address)
	}
	out := Interface{PrivateKey: privateKey, ListenPort: listenPort, Address: addr}
	seen := map[string]bool{}
	for _, p := range s.Peers {
		if !validKey(p.PublicKey) || seen[p.PublicKey] {
			return Interface{}, fmt.Errorf("server sent invalid peer key")
		}
		seen[p.PublicKey] = true
		if len(p.AllowedIPs) == 0 {
			return Interface{}, fmt.Errorf("peer %s has no allowed IPs", p.PublicKey)
		}
		for _, a := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil || pfx != pfx.Masked() || !pfx.Addr().Is4() || pfx.Bits() < network.Bits() || !network.Contains(pfx.Addr()) {
				return Interface{}, fmt.Errorf("peer allowed IP %q is outside the network", a)
			}
		}
		if p.Endpoint != "" {
			if err := validEndpoint(p.Endpoint); err != nil {
				return Interface{}, err
			}
		}
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 3600 {
			return Interface{}, fmt.Errorf("invalid keepalive")
		}
		out.Peers = append(out.Peers, p)
	}
	return out, nil
}

func validEndpoint(ep string) error {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q", ep)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid endpoint port %q", ep)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("invalid endpoint host %q", ep)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid endpoint host %q", ep)
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return fmt.Errorf("invalid endpoint host %q", ep)
			}
		}
	}
	return nil
}

// ValidateEndpoint checks a user-supplied --endpoint flag.
func ValidateEndpoint(ep string) error { return validEndpoint(ep) }

// Render produces the `wg setconf`/`wg syncconf` format. Peer names are not
// written: they are free text from the server and only shown in `status`.
func (i Interface) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", i.PrivateKey, i.ListenPort)
	for _, p := range i.Peers {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", p.PublicKey, strings.Join(p.AllowedIPs, ", "))
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}
