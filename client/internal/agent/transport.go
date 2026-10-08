package agent

import (
	"time"

	"edgeguard/internal/wg"
)

// transport decides whether traffic to the hub goes over UDP or through the
// hub's TLS relay on TCP. It watches one signal: bytes received from the hub.
// The hub keeps every peer alive with 25s keepalives, so silence means the
// current transport is not getting through (typically a hotel or guest
// network blocking UDP).
type transport struct {
	tcp      bool
	since    time.Time
	lastRx   time.Time
	rx       uint64
	rxInMode bool
}

const (
	// Before anything arrives in a mode, the handshake answer comes within a
	// second, so give up on a mode quickly.
	firstContactTimeout = 12 * time.Second
	// Once traffic flowed, allow for the 25s keepalive interval.
	silenceTimeout = 40 * time.Second
	// While on TCP, retry UDP this often if STUN shows UDP works again.
	retryUDPAfter = 5 * time.Minute
)

// step returns true when the transport should be toggled.
func (t *transport) step(now time.Time, hasRelay bool, hub wg.PeerStat, udpWorks bool) bool {
	if t.since.IsZero() {
		t.since = now
	}
	if hub.RxBytes != t.rx {
		if hub.RxBytes > t.rx {
			t.lastRx = now
			t.rxInMode = true
		}
		t.rx = hub.RxBytes
	}
	if !hasRelay {
		return t.tcp // only ever switch back to UDP
	}
	last := t.since
	if t.lastRx.After(last) {
		last = t.lastRx
	}
	limit := firstContactTimeout
	if t.rxInMode {
		limit = silenceTimeout
	}
	if now.Sub(last) > limit {
		return true
	}
	return t.tcp && udpWorks && now.Sub(t.since) > retryUDPAfter
}

func (t *transport) toggle(now time.Time) {
	t.tcp = !t.tcp
	t.since = now
	t.rxInMode = false
}
