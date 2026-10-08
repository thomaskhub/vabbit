package agent

import (
	"time"

	"vabbit/internal/wg"
)

// hubDeadAfter is how long a hub may stay silent before the device moves to
// the next one. Every hub sends a keepalive every 25s, so 40s of nothing means
// it is down (or unreachable from here).
const hubDeadAfter = 40 * time.Second

// hubPicker chooses the hub that carries the network route when the admin has
// marked several. It keeps the current hub while it answers, so traffic never
// flaps between hubs; when it goes silent it moves to the first other hub (in
// the server's order, oldest first) that still answers, or else tries the next
// one in turn. Backup hubs stay ordinary peers meanwhile, so their keepalives
// show whether they are alive.
type hubPicker struct {
	active string
	rx     map[string]uint64
	heard  map[string]time.Time // last time bytes arrived, or when we started trying
}

func newHubPicker() *hubPicker {
	return &hubPicker{rx: map[string]uint64{}, heard: map[string]time.Time{}}
}

// pick returns the active hub's public key ("" when there is none).
func (h *hubPicker) pick(now time.Time, peers []ResolvedPeer, stats map[string]wg.PeerStat) string {
	var hubs []string
	for _, p := range peers {
		if !p.Hub {
			continue
		}
		k := p.PublicKey
		hubs = append(hubs, k)
		if _, ok := h.heard[k]; !ok {
			h.heard[k] = now // a new hub gets a grace period
		}
		if rx := stats[k].RxBytes; rx > h.rx[k] {
			h.heard[k] = now
			h.rx[k] = rx
		} else if rx < h.rx[k] {
			h.rx[k] = rx // counters reset (interface recreated)
		}
	}
	for k := range h.heard {
		if !contains(hubs, k) {
			delete(h.heard, k)
			delete(h.rx, k)
		}
	}
	if len(hubs) == 0 {
		h.active = ""
		return ""
	}
	alive := func(k string) bool { return now.Sub(h.heard[k]) <= hubDeadAfter }
	if contains(hubs, h.active) && alive(h.active) {
		return h.active
	}
	if h.active == "" || !contains(hubs, h.active) {
		// First choice, or the active hub was removed: the first live hub.
		h.active = hubs[0]
		for _, k := range hubs {
			if alive(k) {
				h.active = k
				break
			}
		}
		return h.active
	}
	// The active hub went silent: the first other hub that answers, else the
	// next one in turn (with a fresh grace period, so each gets a fair try).
	next := ""
	for _, k := range hubs {
		if k != h.active && alive(k) {
			next = k
			break
		}
	}
	if next == "" {
		i := index(hubs, h.active)
		next = hubs[(i+1)%len(hubs)]
		h.heard[next] = now
	}
	h.active = next
	return next
}

func contains(s []string, v string) bool { return index(s, v) >= 0 }

func index(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
