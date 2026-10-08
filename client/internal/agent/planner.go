package agent

import (
	"net/netip"
	"slices"
	"time"

	"vabbit/internal/wg"
)

// Path is how traffic to a peer currently flows.
type Path string

const (
	PathDirect     Path = "direct"     // WireGuard session straight to the peer
	PathRelay      Path = "relay"      // no direct session; packets go via the hub
	PathConnecting Path = "connecting" // no direct session and no hub to fall back on
)

const (
	// A live session re-handshakes at least every ~2 minutes because both
	// sides send keepalives every 25s.
	directTTL = 180 * time.Second
	// How long to try one candidate address before moving to the next.
	rotateAfter = 10 * time.Second
)

// ResolvedPeer is a validated peer whose endpoints are IP:port.
type ResolvedPeer struct {
	Peer
	Candidates []netip.AddrPort
}

type peerState struct {
	cands   []netip.AddrPort
	idx     int
	current netip.AddrPort
	setAt   time.Time
}

// Planner decides, every tick, each peer's allowed IPs and which candidate
// address to punch towards. It is pure logic; the caller applies the result.
//
// Strategy:
//   - Both sides of every pair dial each other's candidates (STUN-mapped and
//     LAN addresses) with keepalives, which opens matching NAT mappings on
//     both ends: classic UDP hole punching.
//   - A peer whose handshake is fresh gets its /32: traffic goes direct and
//     WireGuard roaming keeps the endpoint current.
//   - Until then, if there is a hub, the peer gets no allowed IPs so the hub's
//     network-wide route carries the traffic (relay). The punch keeps going
//     in the background and traffic moves to direct as soon as it succeeds.
type Planner struct {
	MyPublic netip.Addr // our STUN-mapped address, if known
	peers    map[string]*peerState
	kick     map[string]bool
}

func NewPlanner() *Planner { return &Planner{peers: map[string]*peerState{}, kick: map[string]bool{}} }

// Kick makes the next plan force a handshake towards the peer.
func (p *Planner) Kick(key string) { p.kick[key] = true }

// Plan computes every peer's config. hubKey is the hub that carries the
// network route (see hubPicker); other hubs are treated like any peer.
func (p *Planner) Plan(now time.Time, n Network, peers []ResolvedPeer, stats map[string]wg.PeerStat, hubKey string) ([]wg.PeerConfig, map[string]Path) {
	if n.SelfHub {
		hubKey = ""
	}

	cfgs := make([]wg.PeerConfig, 0, len(peers))
	paths := make(map[string]Path, len(peers))
	live := map[string]bool{}
	for _, peer := range peers {
		key := peer.PublicKey
		live[key] = true
		st := p.peers[key]
		cands := p.order(peer.Candidates)
		if peer.Hub && len(cands) > 1 {
			// A hub is public by definition: dial its static endpoint only (its
			// other candidates are typically a cloud VM's private address).
			cands = cands[:1]
		}
		if st == nil || !slices.Equal(st.cands, cands) {
			st = &peerState{cands: cands}
			p.peers[key] = st
		}
		stat := stats[key]
		alive := !stat.LastHandshake.IsZero() && now.Sub(stat.LastHandshake) < directTTL

		cfg := wg.PeerConfig{PublicKey: key}
		self32 := netip.PrefixFrom(peer.IP, 32)
		switch {
		case key == hubKey:
			cfg.AllowedIPs = []netip.Prefix{n.CIDR}
		case alive || hubKey == "":
			cfg.AllowedIPs = []netip.Prefix{self32}
		default:
			cfg.AllowedIPs = nil // relay via the hub until the punch succeeds
		}

		switch {
		case alive:
			paths[key] = PathDirect
		case hubKey != "" && key != hubKey:
			paths[key] = PathRelay
		default:
			paths[key] = PathConnecting
		}

		// Keep punching while there is no live session.
		if !alive && len(st.cands) > 0 && (!st.current.IsValid() || now.Sub(st.setAt) >= rotateAfter) {
			if st.current.IsValid() {
				st.idx = (st.idx + 1) % len(st.cands)
			}
			st.current = st.cands[st.idx]
			st.setAt = now
			cfg.Endpoint = st.current
			cfg.Kick = true
		}
		if p.kick[key] {
			cfg.Kick = true
			delete(p.kick, key)
		}
		cfgs = append(cfgs, cfg)
	}
	for k := range p.peers {
		if !live[k] {
			delete(p.peers, k)
		}
	}
	return cfgs, paths
}

// order puts private (LAN) candidates first when the peer is behind the same
// public address as us, since most NATs don't hairpin. Otherwise the server's
// order stands: static endpoint, STUN-mapped address, LAN addresses.
func (p *Planner) order(c []netip.AddrPort) []netip.AddrPort {
	sameNAT := false
	for _, a := range c {
		if p.MyPublic.IsValid() && a.Addr() == p.MyPublic {
			sameNAT = true
		}
	}
	out := slices.Clone(c)
	if sameNAT {
		slices.SortStableFunc(out, func(a, b netip.AddrPort) int {
			pa, pb := a.Addr().IsPrivate(), b.Addr().IsPrivate()
			switch {
			case pa && !pb:
				return -1
			case pb && !pa:
				return 1
			}
			return 0
		})
	}
	return out
}
