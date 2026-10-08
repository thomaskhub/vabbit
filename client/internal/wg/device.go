package wg

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const MTU = 1280

// Device is a running userspace WireGuard interface.
type Device struct {
	Name string
	dev  *device.Device
	tun  tun.Device
	bind *stunBind
	uapi func()
	mu   sync.Mutex
}

// Start creates the TUN interface and brings WireGuard up on it.
func Start(name, privateKey string, port int) (*Device, error) {
	if !ValidIface(name) {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	priv, err := keyHex(privateKey)
	if err != nil {
		return nil, err
	}
	t, err := tun.CreateTUN(name, MTU)
	if err != nil {
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("creating Wintun adapter %s (wintun.dll must be next to vabbit.exe): %w", name, err)
		}
		return nil, fmt.Errorf("creating TUN device %s: %w", name, err)
	}
	if real, err := t.Name(); err == nil {
		name = real
	}
	bind := newSTUNBind()
	dev := device.NewDevice(t, bind, logger())
	d := &Device{Name: name, dev: dev, tun: t, bind: bind}
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", priv, port)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	d.uapi = serveUAPI(name, dev) // lets `wg show` and `vabbit status` read it
	return d, nil
}

func (d *Device) Close() {
	if d.uapi != nil {
		d.uapi()
	}
	d.dev.Close()
}

// STUN returns the public address of WireGuard's socket as seen by server.
func (d *Device) STUN(ctx context.Context, server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.bind.Query(ctx, server)
}

// PeerConfig is the desired state of one peer.
type PeerConfig struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
	// Endpoint, if valid, replaces the peer's current endpoint. Leave it
	// unset to keep whatever WireGuard learned by roaming.
	Endpoint netip.AddrPort
	// Kick forces an immediate handshake attempt (used while hole punching).
	Kick bool
}

const keepalive = 25

// Configure converges the peer set: listed peers are added or updated, every
// other peer is removed. Existing sessions are preserved.
func (d *Device) Configure(peers []PeerConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, err := d.peerStatsLocked()
	if err != nil {
		return err
	}
	var b strings.Builder
	want := map[string]bool{}
	for _, p := range peers {
		h, err := keyHex(p.PublicKey)
		if err != nil {
			return err
		}
		want[p.PublicKey] = true
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\n", h)
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
		if p.Endpoint.IsValid() {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.Kick {
			// Turning keepalive off and on makes wireguard-go send a keepalive
			// now, which starts a handshake towards the (new) endpoint.
			b.WriteString("persistent_keepalive_interval=0\n")
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	}
	for k := range cur {
		if !want[k] {
			h, _ := keyHex(k)
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", h)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return d.dev.IpcSet(b.String())
}

// PeerStat is what WireGuard knows about a peer right now.
type PeerStat struct {
	AllowedIPs    []netip.Prefix
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// Stats returns live peer state keyed by base64 public key.
func (d *Device) Stats() (map[string]PeerStat, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peerStatsLocked()
}

func (d *Device) peerStatsLocked() (map[string]PeerStat, error) {
	s, err := d.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return ParseStats(s), nil
}

// ParseStats parses UAPI "get" output.
func ParseStats(s string) map[string]PeerStat {
	out := map[string]PeerStat{}
	var key string
	var st PeerStat
	var sec int64
	flush := func() {
		if key != "" {
			if sec > 0 {
				st.LastHandshake = time.Unix(sec, 0)
			}
			out[key] = st
		}
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			key, st, sec = "", PeerStat{}, 0
			if b, err := keyB64(v); err == nil {
				key = b
			}
		case "endpoint":
			st.Endpoint, _ = netip.ParseAddrPort(v)
		case "allowed_ip":
			if p, err := netip.ParsePrefix(v); err == nil {
				st.AllowedIPs = append(st.AllowedIPs, p)
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out
}

// Done is closed when the device stops, e.g. because its interface was deleted.
func (d *Device) Done() <-chan struct{} { return d.dev.Wait() }

// logger reports wireguard-go errors except the routine "no known endpoint"
// for peers behind NAT that we can only wait for.
func logger() *device.Logger {
	return &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if !strings.Contains(msg, "no known endpoint") {
				log.Print("wireguard: " + msg)
			}
		},
	}
}
