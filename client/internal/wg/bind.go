package wg

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"edgeguard/internal/stun"

	"golang.zx2c4.com/wireguard/conn"
)

// stunBind wraps wireguard-go's UDP bind so STUN Binding requests go out of,
// and responses come back to, the very socket WireGuard uses. The mapping a
// NAT creates for that socket is what peers must dial to punch through.
type stunBind struct {
	conn.Bind
	mu      sync.Mutex
	pending map[stun.TxID]chan netip.AddrPort
}

func newSTUNBind() *stunBind {
	return &stunBind{Bind: conn.NewDefaultBind(), pending: map[stun.TxID]chan netip.AddrPort{}}
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.filter(fn)
	}
	return wrapped, actual, nil
}

// filter removes STUN packets from a receive batch and hands them to waiting
// queries. Everything else goes to WireGuard untouched.
func (b *stunBind) filter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(packets, sizes, eps)
			if err != nil || n == 0 {
				return n, err
			}
			out := 0
			for i := 0; i < n; i++ {
				p := packets[i][:sizes[i]]
				if stun.IsSTUN(p) {
					b.deliver(p)
					continue
				}
				if out != i {
					// Swap so every slot keeps a distinct backing buffer.
					packets[out], packets[i] = packets[i], packets[out]
					sizes[out] = sizes[i]
					eps[out] = eps[i]
				}
				out++
			}
			if out > 0 {
				return out, nil
			}
		}
	}
}

func (b *stunBind) deliver(p []byte) {
	tx, ok := stun.TxIDOf(p)
	if !ok {
		return
	}
	b.mu.Lock()
	ch := b.pending[tx]
	delete(b.pending, tx)
	b.mu.Unlock()
	if ch == nil {
		return // unsolicited: ignore
	}
	if ap, err := stun.ParseResponse(p, tx); err == nil {
		ch <- ap
	}
}

// Query asks a STUN server for this socket's public address.
func (b *stunBind) Query(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	ep, err := b.Bind.ParseEndpoint(server.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	tx, req := stun.Request()
	ch := make(chan netip.AddrPort, 1)
	b.mu.Lock()
	b.pending[tx] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, tx)
		b.mu.Unlock()
	}()
	if err := b.Bind.Send([][]byte{req}, ep); err != nil {
		return netip.AddrPort{}, err
	}
	select {
	case ap := <-ch:
		return ap, nil
	case <-ctx.Done():
		return netip.AddrPort{}, errors.New("STUN timeout")
	}
}
