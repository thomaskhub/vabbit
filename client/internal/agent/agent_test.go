package agent

import (
	"net/netip"
	"testing"
	"time"

	"vabbit/internal/api"
	"vabbit/internal/wg"
)

const (
	kSelf = "Ag3x3mJ0bWg3J7Ff2x7bX9H1t2Y8l9l3v0QkzQ9dQ3w="
	kA    = "bR8t1H4l2vN6pK0yW3qZ9cX5mJ7dF1sA2gE4hT6uY8o="
	kHub  = "cC3t1H4l2vN6pK0yW3qZ9cX5mJ7dF1sA2gE4hT6uY8o="
)

func syncResp(peers ...api.Peer) api.SyncResponse {
	return api.SyncResponse{Network: api.Network{CIDR: "100.92.0.0/16"}, Address: "100.92.0.5/16", Peers: peers}
}

func TestValidateRejectsHostileData(t *testing.T) {
	ok := api.Peer{PublicKey: kA, IP: "100.92.0.7", Endpoints: []string{"1.2.3.4:5", "vpn.example.com:51820"}}
	if _, err := Validate(syncResp(ok), "100.92.0.0/16", kSelf); err != nil {
		t.Fatalf("valid data rejected: %v", err)
	}
	cases := map[string]api.SyncResponse{
		"ip outside network": syncResp(api.Peer{PublicKey: kA, IP: "8.8.8.8"}),
		"network address":    syncResp(api.Peer{PublicKey: kA, IP: "100.92.0.0"}),
		"our own ip":         syncResp(api.Peer{PublicKey: kA, IP: "100.92.0.5"}),
		"our own key":        syncResp(api.Peer{PublicKey: kSelf, IP: "100.92.0.7"}),
		"bad key":            syncResp(api.Peer{PublicKey: kA + "\n", IP: "100.92.0.7"}),
		"duplicate key":      syncResp(api.Peer{PublicKey: kA, IP: "100.92.0.7"}, api.Peer{PublicKey: kA, IP: "100.92.0.8"}),
		"bad endpoint":       syncResp(api.Peer{PublicKey: kA, IP: "100.92.0.7", Endpoints: []string{"1.2.3.4:1\nallowed_ip=0.0.0.0/0"}}),
	}
	bad := syncResp()
	bad.Network.CIDR = "0.0.0.0/0"
	cases["cidr changed"] = bad
	bad2 := syncResp()
	bad2.Address = "8.8.8.8/16"
	cases["address outside"] = bad2
	for name, s := range cases {
		if _, err := Validate(s, "100.92.0.0/16", kSelf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateEndpoint(t *testing.T) {
	for _, ok := range []string{"1.2.3.4:51820", "[2001:db8::1]:1", "vpn.example.com:443"} {
		if err := ValidateEndpoint(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"1.2.3.4", "a:0", "a b:1", "-a:1"} {
		if ValidateEndpoint(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

var (
	cidr   = netip.MustParsePrefix("100.92.0.0/16")
	ipA    = netip.MustParseAddr("100.92.0.7")
	ipHub  = netip.MustParseAddr("100.92.0.1")
	aPub   = netip.MustParseAddrPort("198.51.100.7:40000")
	aLAN   = netip.MustParseAddrPort("192.168.1.7:51820")
	hubPub = netip.MustParseAddrPort("203.0.113.1:51820")
)

func peers(withHub bool) []ResolvedPeer {
	ps := []ResolvedPeer{{Peer: Peer{Name: "a", PublicKey: kA, IP: ipA}, Candidates: []netip.AddrPort{aPub, aLAN}}}
	if withHub {
		ps = append(ps, ResolvedPeer{Peer: Peer{Name: "hub", PublicKey: kHub, IP: ipHub, Hub: true}, Candidates: []netip.AddrPort{hubPub}})
	}
	return ps
}

func byKey(cfgs []wg.PeerConfig) map[string]wg.PeerConfig {
	m := map[string]wg.PeerConfig{}
	for _, c := range cfgs {
		m[c.PublicKey] = c
	}
	return m
}

func TestPlannerRelaysUntilPunchSucceeds(t *testing.T) {
	p := NewPlanner()
	n := Network{CIDR: cidr}
	t0 := time.Unix(1_700_000_000, 0)

	cfgs, paths := p.Plan(t0, n, peers(true), nil, kHub)
	c := byKey(cfgs)
	if len(c[kA].AllowedIPs) != 0 || paths[kA] != PathRelay {
		t.Fatalf("before punch: want relay with no allowed IPs, got %+v %v", c[kA], paths[kA])
	}
	if c[kA].Endpoint != aPub || !c[kA].Kick {
		t.Fatalf("should punch towards the STUN address first, got %+v", c[kA])
	}
	if got := c[kHub].AllowedIPs; len(got) != 1 || got[0] != cidr {
		t.Fatalf("hub should carry the network route, got %v", got)
	}

	// Nothing yet after 10s: rotate to the next candidate.
	cfgs, _ = p.Plan(t0.Add(10*time.Second), n, peers(true), nil, kHub)
	if c := byKey(cfgs); c[kA].Endpoint != aLAN {
		t.Fatalf("want rotation to LAN candidate, got %+v", c[kA])
	}
	// In between rotations the endpoint is left alone.
	cfgs, _ = p.Plan(t0.Add(12*time.Second), n, peers(true), nil, kHub)
	if c := byKey(cfgs); c[kA].Endpoint.IsValid() || c[kA].Kick {
		t.Fatalf("should not touch endpoint between rotations, got %+v", c[kA])
	}

	// Handshake: go direct and stop steering the endpoint (roaming owns it).
	now := t0.Add(14 * time.Second)
	stats := map[string]wg.PeerStat{kA: {LastHandshake: now.Add(-time.Second)}}
	cfgs, paths = p.Plan(now, n, peers(true), stats, kHub)
	c = byKey(cfgs)
	if paths[kA] != PathDirect || len(c[kA].AllowedIPs) != 1 || c[kA].AllowedIPs[0] != netip.PrefixFrom(ipA, 32) || c[kA].Endpoint.IsValid() {
		t.Fatalf("want direct /32, got %+v %v", c[kA], paths[kA])
	}

	// Session goes stale: back to relay and punching resumes.
	cfgs, paths = p.Plan(now.Add(4*time.Minute), n, peers(true), stats, kHub)
	if c := byKey(cfgs); paths[kA] != PathRelay || len(c[kA].AllowedIPs) != 0 || !c[kA].Kick {
		t.Fatalf("want relay after stale handshake, got %+v %v", c[kA], paths[kA])
	}
}

func TestPlannerWithoutHubRoutesDirectly(t *testing.T) {
	p := NewPlanner()
	cfgs, paths := p.Plan(time.Now(), Network{CIDR: cidr}, peers(false), nil, "")
	c := byKey(cfgs)
	if len(c[kA].AllowedIPs) != 1 || paths[kA] != PathConnecting {
		t.Fatalf("without a hub the /32 must stay on the peer, got %+v %v", c[kA], paths[kA])
	}
}

func TestPlannerAsHub(t *testing.T) {
	p := NewPlanner()
	cfgs, _ := p.Plan(time.Now(), Network{CIDR: cidr, SelfHub: true}, peers(false), nil, "")
	if c := byKey(cfgs); len(c[kA].AllowedIPs) != 1 {
		t.Fatalf("a hub routes every peer's /32, got %+v", c[kA])
	}
}

func TestPlannerPrefersLANBehindSameNAT(t *testing.T) {
	p := NewPlanner()
	p.MyPublic = aPub.Addr()
	cfgs, _ := p.Plan(time.Now(), Network{CIDR: cidr}, peers(false), nil, "")
	if c := byKey(cfgs); c[kA].Endpoint != aLAN {
		t.Fatalf("same public IP: want LAN candidate first, got %v", c[kA].Endpoint)
	}
}

func TestTransportFallsBackToTCPAndRetriesUDP(t *testing.T) {
	var tr transport
	t0 := time.Unix(1_700_000_000, 0)
	// UDP blocked: nothing from the hub for 12s -> TCP.
	if tr.step(t0, true, wg.PeerStat{}, false) || tr.step(t0.Add(10*time.Second), true, wg.PeerStat{}, false) {
		t.Fatal("switched too early")
	}
	if !tr.step(t0.Add(13*time.Second), true, wg.PeerStat{}, false) {
		t.Fatal("should fall back to TCP")
	}
	tr.toggle(t0.Add(13 * time.Second))
	// Traffic flows over TCP: stay, even with 30s gaps between keepalives.
	now := t0.Add(15 * time.Second)
	for i := uint64(1); i <= 12; i++ {
		now = now.Add(30 * time.Second)
		if tr.step(now, true, wg.PeerStat{RxBytes: i * 100}, false) {
			t.Fatalf("left a working TCP path at step %d", i)
		}
	}
	// STUN works again (left the hotel): after 5 min on TCP, retry UDP.
	if !tr.step(now.Add(time.Second), true, wg.PeerStat{RxBytes: 1300}, true) {
		t.Fatal("should retry UDP once UDP works")
	}
	tr.toggle(now)
	// No relay offered: never move to TCP.
	var tr2 transport
	if tr2.step(t0, false, wg.PeerStat{}, false) || tr2.step(t0.Add(time.Minute), false, wg.PeerStat{}, false) {
		t.Fatal("switched to TCP without a relay")
	}
}
