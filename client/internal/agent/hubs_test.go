package agent

import (
	"net/netip"
	"testing"
	"time"

	"vabbit/internal/wg"
)

const kHub2 = "dD3t1H4l2vN6pK0yW3qZ9cX5mJ7dF1sA2gE4hT6uY8o="

func twoHubs() []ResolvedPeer {
	ps := peers(true)
	return append(ps, ResolvedPeer{Peer: Peer{Name: "hub2", PublicKey: kHub2, IP: netip.MustParseAddr("100.92.0.2"), Hub: true},
		Candidates: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:51820")}})
}

func TestHubFailover(t *testing.T) {
	h := newHubPicker()
	t0 := time.Now()
	ps := twoHubs()
	rx := map[string]uint64{kHub: 0, kHub2: 0}
	stats := func() map[string]wg.PeerStat {
		return map[string]wg.PeerStat{kHub: {RxBytes: rx[kHub]}, kHub2: {RxBytes: rx[kHub2]}}
	}
	if got := h.pick(t0, ps, stats()); got != kHub {
		t.Fatalf("first pick should be the first hub, got %s", got)
	}
	// Both answer: stay on the first.
	for i := 1; i <= 4; i++ {
		rx[kHub] += 32
		rx[kHub2] += 32
		if got := h.pick(t0.Add(time.Duration(i)*25*time.Second), ps, stats()); got != kHub {
			t.Fatalf("switched away from a live hub at step %d", i)
		}
	}
	// hub goes silent at t0+100s; hub2 keeps answering.
	now := t0.Add(100 * time.Second)
	for now.Before(t0.Add(100*time.Second + hubDeadAfter)) {
		now = now.Add(5 * time.Second)
		rx[kHub2] += 32
		if got := h.pick(now, ps, stats()); got != kHub {
			t.Fatalf("switched before the hub was declared dead (%v)", now.Sub(t0))
		}
	}
	now = now.Add(5 * time.Second)
	rx[kHub2] += 32
	if got := h.pick(now, ps, stats()); got != kHub2 {
		t.Fatalf("no failover to the live backup, got %s", got)
	}
	// hub comes back: stay on hub2 (no flapping).
	rx[kHub] += 32
	rx[kHub2] += 32
	if got := h.pick(now.Add(5*time.Second), ps, stats()); got != kHub2 {
		t.Fatal("flapped back to the first hub")
	}
}

func TestHubFailoverAllSilent(t *testing.T) {
	// e.g. UDP blocked: nothing arrives from any hub. Each gets a turn.
	h := newHubPicker()
	t0 := time.Now()
	ps := twoHubs()
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		seen[h.pick(t0.Add(time.Duration(i)*5*time.Second), ps, nil)] = true
	}
	if !seen[kHub] || !seen[kHub2] {
		t.Fatalf("hubs not tried in turn: %v", seen)
	}
}

func TestHubPickerRemovedHub(t *testing.T) {
	h := newHubPicker()
	t0 := time.Now()
	if got := h.pick(t0, twoHubs(), nil); got != kHub {
		t.Fatal(got)
	}
	// The admin unsets the first hub: move to the other at once.
	ps := twoHubs()
	ps[len(ps)-2].Hub = false
	if got := h.pick(t0.Add(time.Second), ps, nil); got != kHub2 {
		t.Fatalf("got %s", got)
	}
	if got := h.pick(t0.Add(2*time.Second), peers(false), nil); got != "" {
		t.Fatalf("no hubs left, got %s", got)
	}
}

func TestPlannerBackupHubIsOrdinaryPeer(t *testing.T) {
	p := NewPlanner()
	n := Network{CIDR: cidr}
	cfgs, _ := p.Plan(time.Now(), n, twoHubs(), nil, kHub2)
	c := byKey(cfgs)
	if got := c[kHub2].AllowedIPs; len(got) != 1 || got[0] != cidr {
		t.Fatalf("active hub should carry the network route, got %v", got)
	}
	if got := c[kHub].AllowedIPs; len(got) > 0 && got[0] == cidr {
		t.Fatalf("backup hub must not carry the network route, got %v", got)
	}
}
