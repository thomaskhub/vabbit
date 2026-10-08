// Package agent keeps a device's WireGuard interface in line with the control
// plane and does NAT traversal: it punches holes directly between peers and
// routes through the hub only while no direct path works.
package agent

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"vabbit/internal/api"
	"vabbit/internal/wg"
)

// Network is the validated view of one sync response.
type Network struct {
	Address netip.Prefix // our VPN address with the network prefix length
	CIDR    netip.Prefix
	SelfHub bool
	// SelfName is this device's name as the server knows it (an admin may have renamed it).
	SelfName string
	Peers    []Peer
}

type Peer struct {
	Name      string
	PublicKey string
	IP        netip.Addr
	Hub       bool
	Endpoints []string // host:port, best first; may contain DNS names (static endpoints)
	Relay     *api.Relay
}

// Validate checks everything the control plane sent before it is used. The
// control plane may introduce peers, but every address it hands out must sit
// inside the network CIDR pinned at enrollment, so it can never route the
// device's other traffic into the VPN.
func Validate(s api.SyncResponse, pinnedCIDR, selfPublicKey string) (Network, error) {
	cidr, err := netip.ParsePrefix(pinnedCIDR)
	if err != nil {
		return Network{}, fmt.Errorf("bad pinned CIDR: %w", err)
	}
	if s.Network.CIDR != pinnedCIDR {
		return Network{}, fmt.Errorf("server network CIDR %q differs from enrolled %q", s.Network.CIDR, pinnedCIDR)
	}
	addr, err := netip.ParsePrefix(s.Address)
	if err != nil || !addr.Addr().Is4() || addr.Bits() != cidr.Bits() || !cidr.Contains(addr.Addr()) {
		return Network{}, fmt.Errorf("server sent invalid address %q", s.Address)
	}
	n := Network{Address: addr, CIDR: cidr, SelfHub: s.Self.Hub, SelfName: s.Self.Name}
	seenKey := map[string]bool{selfPublicKey: true}
	seenIP := map[netip.Addr]bool{addr.Addr(): true}
	for _, p := range s.Peers {
		if !wg.ValidKey(p.PublicKey) || seenKey[p.PublicKey] {
			return Network{}, fmt.Errorf("server sent invalid or duplicate peer key")
		}
		seenKey[p.PublicKey] = true
		ip, err := netip.ParseAddr(p.IP)
		if err != nil || !ip.Is4() || !cidr.Contains(ip) || ip == cidr.Addr() || seenIP[ip] {
			return Network{}, fmt.Errorf("peer address %q is invalid or outside the network", p.IP)
		}
		seenIP[ip] = true
		if len(p.Endpoints) > 16 {
			return Network{}, fmt.Errorf("too many endpoints for peer %s", p.PublicKey)
		}
		for _, e := range p.Endpoints {
			if err := ValidateEndpoint(e); err != nil {
				return Network{}, err
			}
		}
		var rel *api.Relay
		if p.Relay != nil && p.Hub {
			if ValidateEndpoint(p.Relay.Addr) != nil || !fingerprintRE.MatchString(p.Relay.Fingerprint) {
				return Network{}, fmt.Errorf("invalid relay for peer %s", p.PublicKey)
			}
			rel = p.Relay
		}
		n.Peers = append(n.Peers, Peer{Name: sanitizeName(p.Name), PublicKey: p.PublicKey, IP: ip, Hub: p.Hub, Endpoints: p.Endpoints, Relay: rel})
	}
	return n, nil
}

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '?'
	}, s)
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

// ValidateEndpoint checks a host:port with an IP literal or a DNS name.
func ValidateEndpoint(ep string) error {
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
