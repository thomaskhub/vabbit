package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func aps(ss ...string) []netip.AddrPort {
	out := make([]netip.AddrPort, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddrPort(s)
	}
	return out
}

func TestUsableLocal(t *testing.T) {
	vpn := netip.MustParsePrefix("100.92.0.0/16")
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.168.1.5", true},
		{"203.0.113.7", true},
		{"169.254.1.1", false},     // IPv4 link-local
		{"100.92.3.4", false},      // inside the VPN
		{"127.0.0.2", false},       // loopback
		{"0.0.0.0", false},         // unspecified
		{"224.0.0.1", false},       // multicast
		{"2001:db8::5", true},      // global IPv6
		{"fd00:7::11", true},       // unique-local
		{"fe80::1", false},         // IPv6 link-local
		{"::1", false},             // IPv6 loopback
		{"ff02::1", false},         // IPv6 multicast
		{"::", false},              // IPv6 unspecified
		{"::ffff:192.0.2.9", true}, // IPv4-mapped counts as the IPv4 address
	} {
		if got := usableLocal(netip.MustParseAddr(tc.ip), vpn); got != tc.want {
			t.Errorf("usableLocal(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestLimitLocal(t *testing.T) {
	v4 := addrs("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7")
	if got := limitLocal(v4, 5); !slices.Equal(got, v4[:5]) {
		t.Errorf("IPv4 only must keep the first five in order, got %v", got)
	}
	dual := addrs("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "fd00::1", "fd00::2", "fd00::3", "fd00::4")
	got := limitLocal(dual, 4)
	if !slices.Equal(got, addrs("10.0.0.1", "fd00::1", "10.0.0.2", "fd00::2")) {
		t.Errorf("dual stack must share the room between the families, got %v", got)
	}
	if got := limitLocal(addrs("10.0.0.1", "fd00::1"), 5); len(got) != 2 {
		t.Errorf("fewer addresses than room must all be kept, got %v", got)
	}
	if got := limitLocal(dual, 0); len(got) != 0 {
		t.Errorf("no room, got %v", got)
	}
	if got := limitLocal(addrs("fd00::1", "fd00::2", "fd00::3"), 2); !slices.Equal(got, addrs("fd00::1", "fd00::2")) {
		t.Errorf("IPv6 only, got %v", got)
	}
}

func TestFamiliesOf(t *testing.T) {
	for _, tc := range []struct {
		in     []netip.Addr
		v4, v6 bool
	}{
		{nil, false, false},
		{addrs("10.0.0.1"), true, false},
		{addrs("fd00::1"), false, true},
		{addrs("10.0.0.1", "2001:db8::1"), true, true},
	} {
		v4, v6 := familiesOf(tc.in)
		if v4 != tc.v4 || v6 != tc.v6 {
			t.Errorf("familiesOf(%v) = %v %v, want %v %v", tc.in, v4, v6, tc.v4, tc.v6)
		}
	}
}

func TestFilterFamilies(t *testing.T) {
	mixed := aps("203.0.113.7:51820", "[2001:db8::5]:51820", "[::ffff:192.0.2.9]:51820")
	if got := filterFamilies(mixed, false, true); !slices.Equal(got, aps("[2001:db8::5]:51820")) {
		t.Errorf("IPv6-only host must drop IPv4 candidates (also the mapped form), got %v", got)
	}
	if got := filterFamilies(mixed, true, false); len(got) != 2 {
		t.Errorf("IPv4-only host must drop IPv6 candidates, got %v", got)
	}
	if got := filterFamilies(mixed, true, true); !slices.Equal(got, mixed) {
		t.Errorf("dual stack keeps all, got %v", got)
	}
	if got := filterFamilies(mixed, false, false); !slices.Equal(got, mixed) {
		t.Errorf("unknown families keep all, got %v", got)
	}
	only4 := aps("203.0.113.7:51820")
	if got := filterFamilies(only4, false, true); !slices.Equal(got, only4) {
		t.Errorf("never filter down to nothing, got %v", got)
	}
}

func TestSummariseMapped(t *testing.T) {
	never := func(netip.Addr) bool { return false }
	always := func(netip.Addr) bool { return true }
	const symmetric = "symmetric (direct paths unlikely; using hub)"
	for _, tc := range []struct {
		name       string
		mapped     []netip.AddrPort
		isLocal    func(netip.Addr) bool
		wantCands  []netip.AddrPort
		wantPublic string
		wantNAT    string
	}{
		{"nothing mapped", nil, never, nil, "", "unknown"},
		{"IPv4 easy NAT (two servers agree)", aps("203.0.113.7:40000", "203.0.113.7:40000"), never, aps("203.0.113.7:40000"), "203.0.113.7", "easy"},
		{"IPv4 symmetric NAT", aps("203.0.113.7:40000", "203.0.113.7:40001"), never, aps("203.0.113.7:40000"), "203.0.113.7", symmetric},
		{"IPv4 public address", aps("203.0.113.7:51820"), always, aps("203.0.113.7:51820"), "203.0.113.7", "none (public IP)"},
		{"IPv6 only, easy", aps("[2001:db8::5]:51820"), never, aps("[2001:db8::5]:51820"), "2001:db8::5", "easy"},
		{"IPv6 public address", aps("[2001:db8::5]:51820"), always, aps("[2001:db8::5]:51820"), "2001:db8::5", "none (public IP)"},
		{"both families: one candidate each, public is the IPv4 one", aps("203.0.113.7:40000", "[2001:db8::5]:51820", "203.0.113.7:40000", "[2001:db8::5]:51820"), never,
			aps("203.0.113.7:40000", "[2001:db8::5]:51820"), "203.0.113.7", "easy"},
		{"IPv6 symmetric while IPv4 is fine", aps("203.0.113.7:40000", "[2001:db8::5]:1", "[2001:db8::5]:2"), never,
			aps("203.0.113.7:40000", "[2001:db8::5]:1"), "203.0.113.7", symmetric},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cands, public, nat := summariseMapped(tc.mapped, tc.isLocal)
			if !slices.Equal(cands, tc.wantCands) {
				t.Errorf("candidates = %v, want %v", cands, tc.wantCands)
			}
			if public.String() != tc.wantPublic && !(tc.wantPublic == "" && !public.IsValid()) {
				t.Errorf("public = %v, want %q", public, tc.wantPublic)
			}
			if nat != tc.wantNAT {
				t.Errorf("nat = %q, want %q", nat, tc.wantNAT)
			}
		})
	}
}

func TestResolveEndpoint(t *testing.T) {
	lookup := func(m map[string][]string) lookupFunc {
		return func(_ context.Context, host string) ([]netip.Addr, error) {
			v, ok := m[host]
			if !ok {
				return nil, errors.New("no such host")
			}
			return addrs(v...), nil
		}
	}
	dns := lookup(map[string][]string{
		"dual.example":   {"2001:db8::7", "203.0.113.9", "2001:db8::8"},
		"v6only.example": {"64:ff9b::cb00:7109"}, // what a DNS64 resolver returns for an IPv4-only name
		"many.example":   {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"},
	})
	ctx := context.Background()
	for _, tc := range []struct {
		in      string
		want    []netip.AddrPort
		wantErr bool
	}{
		{"203.0.113.9:51820", aps("203.0.113.9:51820"), false},
		{"[2001:db8::1]:51820", aps("[2001:db8::1]:51820"), false},
		{"dual.example:51820", aps("203.0.113.9:51820", "[2001:db8::7]:51820", "[2001:db8::8]:51820"), false}, // IPv4 first
		{"v6only.example:443", aps("[64:ff9b::cb00:7109]:443"), false},
		{"many.example:51820", aps("192.0.2.1:51820", "192.0.2.2:51820", "192.0.2.3:51820", "192.0.2.4:51820"), false}, // capped
		{"missing.example:51820", nil, true},
		{"dual.example", nil, true}, // no port
		{"dual.example:notaport", nil, true},
	} {
		got, err := resolveEndpoint(ctx, tc.in, dns)
		if (err != nil) != tc.wantErr {
			t.Errorf("resolveEndpoint(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("resolveEndpoint(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFirstPerFamily(t *testing.T) {
	got := firstPerFamily(aps("[2001:db8::7]:3478", "203.0.113.9:3478", "[2001:db8::8]:3478", "203.0.113.10:3478"))
	if !slices.Equal(got, aps("203.0.113.9:3478", "[2001:db8::7]:3478")) {
		t.Errorf("firstPerFamily = %v", got)
	}
}

func TestPlannerOrderFamilies(t *testing.T) {
	p := NewPlanner()
	c := aps("203.0.113.7:51820", "[2001:db8::5]:51820", "[fd00:7::12]:51820")
	if got := p.order(c); !slices.Equal(got, c) {
		t.Errorf("unknown families must leave the list alone, got %v", got)
	}
	p.HaveV6 = true
	if got := p.order(c); !slices.Equal(got, aps("[2001:db8::5]:51820", "[fd00:7::12]:51820")) {
		t.Errorf("IPv6-only host must drop IPv4 candidates, got %v", got)
	}
	p.LocalV6 = addrs("fd00:7::11")
	if got := p.order(c); !slices.Equal(got, aps("[fd00:7::12]:51820", "[2001:db8::5]:51820")) {
		t.Errorf("a candidate in our own /64 must be tried first, got %v", got)
	}
	q := NewPlanner()
	q.HaveV4 = true
	if got := q.order(c); !slices.Equal(got, aps("203.0.113.7:51820")) {
		t.Errorf("IPv4-only host must drop IPv6 candidates, got %v", got)
	}
}

func TestHubTargetMatchesPlan(t *testing.T) {
	hub := ResolvedPeer{Peer: Peer{Name: "hub", PublicKey: kHub, IP: ipHub, Hub: true},
		Candidates: aps("203.0.113.7:51820", "[2001:db8::5]:51820")}
	p := NewPlanner()
	p.HaveV6 = true // IPv6-only host: the planner skips the hub's first (IPv4) address
	want := netip.MustParseAddrPort("[2001:db8::5]:51820")
	if got := p.HubTarget(hub); got != want {
		t.Fatalf("HubTarget = %v, want %v", got, want)
	}
	cfgs, _ := p.Plan(time.Now(), Network{CIDR: cidr}, []ResolvedPeer{hub}, nil, kHub)
	if len(cfgs) != 1 || cfgs[0].Endpoint != want {
		t.Errorf("Plan dials %v, HubTarget says %v", cfgs, want)
	}
	if got := p.HubTarget(ResolvedPeer{}); got.IsValid() {
		t.Errorf("HubTarget without candidates = %v, want invalid", got)
	}
}

func TestQueryMappedParallelAndOrdered(t *testing.T) {
	dns := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "a.example":
			return addrs("192.0.2.1", "2001:db8::1"), nil
		case "b.example":
			return addrs("192.0.2.2", "2001:db8::2"), nil
		}
		return nil, errors.New("no such host")
	}
	answer := map[string]string{
		"192.0.2.1:3478": "198.51.100.1:1000", "[2001:db8::1]:3478": "[2001:db8:f::1]:1000",
		"192.0.2.2:3478": "198.51.100.1:2000", "[2001:db8::2]:3478": "[2001:db8:f::1]:2000",
	}
	query := func(ctx context.Context, s netip.AddrPort) (netip.AddrPort, error) {
		// The first server answers last, and IPv6 on the second server is blackholed.
		delay := 10 * time.Millisecond
		if s.Addr() == netip.MustParseAddr("192.0.2.1") {
			delay = 400 * time.Millisecond
		}
		if s.Addr() == netip.MustParseAddr("2001:db8::2") {
			delay = time.Hour
		}
		ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		select {
		case <-time.After(delay):
			return netip.MustParseAddrPort(answer[s.String()]), nil
		case <-ctx.Done():
			return netip.AddrPort{}, errors.New("STUN timeout")
		}
	}
	start := time.Now()
	got := queryMapped(context.Background(), []string{"a.example:3478", "missing.example:3478", "b.example:3478"}, true, true, dns, query)
	if d := time.Since(start); d > 800*time.Millisecond { // one after another would take over 900 ms
		t.Errorf("queries took %v; they must run at once", d)
	}
	want := aps("198.51.100.1:1000", "[2001:db8:f::1]:1000", "198.51.100.1:2000")
	if !slices.Equal(got, want) {
		t.Errorf("queryMapped = %v, want %v", got, want)
	}
	if got := queryMapped(context.Background(), []string{"a.example:3478"}, true, false, dns, query); !slices.Equal(got, aps("198.51.100.1:1000")) {
		t.Errorf("IPv4-only host must only ask over IPv4, got %v", got)
	}
}

func TestUDPWorksTo(t *testing.T) {
	v4, v6 := netip.MustParseAddrPort("203.0.113.7:51820"), netip.MustParseAddrPort("[2001:db8::5]:51820")
	only6 := aps("[2001:db8:f::1]:1000")
	for _, tc := range []struct {
		target netip.AddrPort
		stun   []netip.AddrPort
		want   bool
	}{
		{v4, only6, false}, // IPv6 STUN says nothing about UDP to an IPv4 hub
		{v6, only6, true},
		{netip.AddrPort{}, only6, true},
		{netip.AddrPort{}, nil, false},
		{v4, aps("198.51.100.1:1000", "[2001:db8:f::1]:1000"), true},
	} {
		if got := udpWorksTo(tc.target, tc.stun); got != tc.want {
			t.Errorf("udpWorksTo(%v, %v) = %v, want %v", tc.target, tc.stun, got, tc.want)
		}
	}
}
