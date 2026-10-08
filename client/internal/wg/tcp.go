package wg

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"edgeguard/internal/relay"

	"golang.zx2c4.com/wireguard/conn"
)

// tcpTunnel sends packets addressed to one endpoint (the hub) through the
// hub's TLS relay instead of UDP. Packets coming back are handed to WireGuard
// as if they arrived from that endpoint over UDP, so WireGuard's view of the
// peer never changes and sessions survive switching in either direction.
type tcpTunnel struct {
	mu         sync.Mutex
	target     string // DstToString of the intercepted endpoint; "" when off
	ep         conn.Endpoint
	addr, fp   string
	conn       net.Conn
	connecting bool
	queued     [][]byte // packets sent while connecting, flushed on connect
	recv       chan []byte
	closed     chan struct{}
}

// open returns the extra receive function for WireGuard, valid until close.
func (t *tcpTunnel) open() conn.ReceiveFunc {
	t.mu.Lock()
	recv, closed := make(chan []byte, 256), make(chan struct{})
	t.recv, t.closed = recv, closed
	t.mu.Unlock()
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p := <-recv:
			t.mu.Lock()
			ep := t.ep
			t.mu.Unlock()
			if ep == nil {
				return 0, nil
			}
			sizes[0] = copy(packets[0], p)
			eps[0] = ep
			return 1, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	}
}

func (t *tcpTunnel) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed != nil {
		close(t.closed)
		t.closed = nil
	}
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

func (t *tcpTunnel) intercepts(ep conn.Endpoint) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.target != "" && ep.DstToString() == t.target
}

func (t *tcpTunnel) enable(ep conn.Endpoint, addr, fp string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.target == ep.DstToString() && t.addr == addr && t.fp == fp {
		return
	}
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.target, t.ep, t.addr, t.fp = ep.DstToString(), ep, addr, fp
}

func (t *tcpTunnel) disable() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.target, t.ep, t.queued = "", nil, nil
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

func (t *tcpTunnel) active() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.target != ""
}

const maxQueued = 32

// send writes packets to the tunnel. While (re)connecting a few packets are
// queued and the rest dropped, like UDP loss; WireGuard retransmits.
func (t *tcpTunnel) send(bufs [][]byte) error {
	t.mu.Lock()
	c := t.conn
	if c == nil {
		for _, b := range bufs {
			if len(t.queued) < maxQueued {
				t.queued = append(t.queued, append([]byte(nil), b...))
			}
		}
		if !t.connecting && t.target != "" {
			t.connecting = true
			go t.connect(t.addr, t.fp)
		}
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()
	for _, b := range bufs {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := relay.WriteFrame(c, b); err != nil {
			t.drop(c)
			return nil
		}
	}
	return nil
}

func (t *tcpTunnel) drop(c net.Conn) {
	c.Close()
	t.mu.Lock()
	if t.conn == c {
		t.conn = nil
	}
	t.mu.Unlock()
}

func (t *tcpTunnel) connect(addr, fp string) {
	c, err := relay.Dial(addr, fp, 10*time.Second)
	t.mu.Lock()
	t.connecting = false
	if err != nil || t.target == "" || t.addr != addr || t.fp != fp || t.closed == nil {
		t.queued = nil
		t.mu.Unlock()
		if c != nil {
			c.Close()
		}
		if err != nil {
			time.Sleep(2 * time.Second) // crude backoff; the next send retries
		}
		return
	}
	t.conn = c
	recv, closed := t.recv, t.closed
	queued := t.queued
	t.queued = nil
	t.mu.Unlock()
	for _, b := range queued {
		if relay.WriteFrame(c, b) != nil {
			t.drop(c)
			return
		}
	}

	go func() {
		buf := make([]byte, relay.MaxPacket)
		for {
			n, err := relay.ReadFrame(c, buf)
			if err != nil {
				t.drop(c)
				return
			}
			p := append([]byte(nil), buf[:n]...)
			select {
			case recv <- p:
			case <-closed:
				return
			default: // receiver is behind: drop like a full socket buffer would
			}
		}
	}()
}

// UseTCPRelay sends everything for the peer at hub through the hub's TLS
// relay at addr (pinned by fingerprint) instead of UDP.
func (d *Device) UseTCPRelay(hub netip.AddrPort, addr, fingerprint string) error {
	ep, err := d.bind.Bind.ParseEndpoint(hub.String())
	if err != nil {
		return err
	}
	d.bind.tcp.enable(ep, addr, fingerprint)
	return nil
}

// UseUDP switches back to plain UDP for every peer.
func (d *Device) UseUDP() { d.bind.tcp.disable() }

// TCPRelayActive reports whether hub traffic is tunnelled over TCP.
func (d *Device) TCPRelayActive() bool { return d.bind.tcp.active() }
