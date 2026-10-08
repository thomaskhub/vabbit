package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"vabbit/internal/api"
	"vabbit/internal/hosts"
	"vabbit/internal/relay"
	"vabbit/internal/state"
	"vabbit/internal/wg"
)

// ErrRemoved means the control plane no longer knows this device.
var ErrRemoved = errors.New("this device was removed from the network")

var DefaultSTUN = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

type Options struct {
	Iface        string
	Device       state.Device
	Client       *api.Client
	STUNServers  []string
	SyncInterval time.Duration
	// TCPRelay is the address a hub serves its TLS relay on (e.g. ":443"),
	// for devices on networks that block UDP. Empty disables it.
	TCPRelay string
	// Domain is the domain of the names written to the hosts file ("" = off, see EffectiveDomain).
	Domain string
	// HostsFile is the file that gets the names; empty = /etc/hosts.
	HostsFile string
	Logf      func(format string, args ...any)
}

const tick = 2 * time.Second

// Run brings the interface up and keeps it converged until ctx is cancelled.
func Run(ctx context.Context, o Options) error {
	selfPub, err := wg.PublicKey(o.Device.PrivateKey)
	if err != nil {
		return err
	}
	dev, err := wg.Start(o.Iface, o.Device.PrivateKey, o.Device.ListenPort)
	if err != nil {
		return err
	}
	defer dev.Close()
	writeTransport(dev.Name, "UDP")
	defer os.Remove(TransportFile(dev.Name))

	planner := NewPlanner()
	var (
		netw       Network
		resolved   []ResolvedPeer
		haveNet    bool
		lastSync   time.Time
		failures   int
		lastPaths  = map[string]Path{}
		lastAddr   netip.Prefix
		lastHub    bool
		lastCands  string
		staticEP   = o.Device.Endpoint
		peerByName = map[string]string{}
		udpWorks   bool
		trans      transport
		hubs       = newHubPicker()
		lastHubKey string
		relaySrv   *relay.Server
		relayInfo  *api.Relay
		lastHosts  []hosts.Entry
		hostsFile  = o.HostsFile
	)
	if hostsFile == "" {
		hostsFile = hosts.DefaultFile
	}
	// The names of the other devices are written to the hosts file after every good sync and the block
	// is taken out again when the agent stops.
	if o.Domain == "" { // the feature is off: take out a block that an earlier run left
		if _, err := hosts.Apply(hostsFile, o.Iface, nil); err != nil {
			o.Logf("could not clean the device names out of %s: %v", hostsFile, err)
		}
	}
	defer func() {
		if lastHosts != nil {
			if _, err := hosts.Apply(hostsFile, o.Iface, nil); err != nil {
				o.Logf("could not remove the device names from %s: %v", hostsFile, err)
			}
		}
	}()
	defer func() {
		if relaySrv != nil {
			relaySrv.Close()
		}
	}()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		wait := o.SyncInterval
		if failures > 0 {
			wait = min(o.SyncInterval*time.Duration(1<<min(failures, 4)), 5*time.Minute)
		}
		if !haveNet || time.Since(lastSync) >= wait {
			lastSync = time.Now()
			cands, public, nat := gatherCandidates(ctx, dev, o.STUNServers, o.Device.ListenPort, netipCIDR(o.Device.NetworkCIDR))
			planner.MyPublic = public
			udpWorks = public.IsValid()
			if cands == nil {
				cands = []string{}
			}
			if c := strings.Join(cands, ","); c != lastCands {
				lastCands = c
				o.Logf("candidates: %s (NAT: %s)", orNone(c), nat)
			}
			s, err := o.Client.Sync(ctx, staticEP, cands, relayInfo)
			switch {
			case errors.Is(err, api.ErrUnauthorized):
				if strings.Contains(err.Error(), "expired") {
					return fmt.Errorf("%w: its access expired", ErrRemoved)
				}
				return ErrRemoved
			case err != nil:
				failures++
				o.Logf("sync failed, keeping current config: %v", err)
			default:
				n, err := Validate(s, o.Device.NetworkCIDR, selfPub)
				if err != nil {
					failures++
					o.Logf("rejected control plane data: %v", err)
					break
				}
				failures = 0
				netw, haveNet = n, true
				resolved = resolve(ctx, n.Peers)
				for _, p := range n.Peers {
					peerByName[p.PublicKey] = p.Name
				}
				if entries, skipped := hostEntries(o.Device.Name, n.Address.Addr(), n.Peers, o.Domain); !slices.Equal(entries, lastHosts) {
					if _, err := hosts.Apply(hostsFile, o.Iface, entries); err != nil {
						o.Logf("could not write the device names to %s: %v", hostsFile, err)
					} else {
						lastHosts = entries
						if skipped > 0 {
							o.Logf("%d device name(s) skipped: not valid host names or used twice", skipped)
						}
					}
				}
				if n.Address != lastAddr || n.SelfHub != lastHub {
					if err := dev.SetAddress(n.Address); err != nil {
						return err
					}
					if err := dev.SetForwarding(n.SelfHub); err != nil {
						return err
					}
					o.Logf("interface %s up with %s (hub: %v)", dev.Name, n.Address, n.SelfHub)
					lastAddr, lastHub = n.Address, n.SelfHub
				}
				switch {
				case n.SelfHub && relaySrv == nil && o.TCPRelay != "" && staticEP != "":
					srv, info, err := startRelay(o.TCPRelay, staticEP, o.Device.ListenPort)
					if err != nil {
						o.Logf("TCP relay not started (%v); devices on UDP-blocked networks can't reach this hub", err)
						o.TCPRelay = "" // don't retry every sync
						break
					}
					relaySrv, relayInfo = srv, info
					lastSync = time.Time{} // publish it right away
					o.Logf("TCP relay for UDP-blocked networks on %s", info.Addr)
				case !n.SelfHub && relaySrv != nil:
					relaySrv.Close()
					relaySrv, relayInfo = nil, nil
				}
			}
		}

		if haveNet {
			stats, err := dev.Stats()
			if err != nil {
				return err
			}
			now := time.Now()
			hubKey := ""
			if !netw.SelfHub {
				hubKey = hubs.pick(now, resolved, stats)
				if hubKey != lastHubKey {
					if lastHubKey != "" {
						o.Logf("hub %s stopped answering; using hub %s", peerByName[lastHubKey], peerByName[hubKey])
						// Start over on UDP with the new hub.
						if trans.tcp {
							dev.UseUDP()
							writeTransport(dev.Name, "UDP")
						}
						trans = transport{}
					}
					lastHubKey = hubKey
				}
				hub := peerByKey(resolved, hubKey)
				var hubStat wg.PeerStat
				hasRelay := hub != nil && hub.Relay != nil && len(hub.Candidates) > 0
				if hub != nil {
					hubStat = stats[hub.PublicKey]
				}
				if trans.step(now, hasRelay, hubStat, udpWorks) {
					trans.toggle(now)
					if trans.tcp {
						if err := dev.UseTCPRelay(hub.Candidates[0], hub.Relay.Addr, hub.Relay.Fingerprint); err != nil {
							return err
						}
						o.Logf("no UDP from the hub; tunnelling over TCP to %s", hub.Relay.Addr)
						writeTransport(dev.Name, "TCP relay "+hub.Relay.Addr+" (UDP blocked)")
					} else {
						dev.UseUDP()
						o.Logf("using UDP to the hub")
						writeTransport(dev.Name, "UDP")
					}
					if hub != nil {
						planner.Kick(hub.PublicKey)
					}
				}
			}
			cfgs, paths := planner.Plan(now, netw, resolved, stats, hubKey)
			if err := dev.Configure(cfgs); err != nil {
				return fmt.Errorf("configuring peers: %w", err)
			}
			for k, p := range paths {
				if lastPaths[k] != p {
					detail := ""
					if p == PathDirect {
						if s, err := dev.Stats(); err == nil && s[k].Endpoint.IsValid() {
							detail = " via " + s[k].Endpoint.String()
						}
					}
					o.Logf("peer %s: %s%s", peerByName[k], p, detail)
				}
			}
			lastPaths = paths
		}

		select {
		case <-ctx.Done():
			return nil
		case <-dev.Done():
			return errors.New("interface was removed")
		case <-t.C:
		}
	}
}

// TransportFile records how this device reaches the hub, for `vabbit status`.
func TransportFile(iface string) string { return "/var/run/wireguard/" + iface + ".transport" }

func writeTransport(iface, s string) { _ = os.WriteFile(TransportFile(iface), []byte(s+"\n"), 0o600) }

func peerByKey(peers []ResolvedPeer, key string) *ResolvedPeer {
	for i := range peers {
		if key != "" && peers[i].PublicKey == key {
			return &peers[i]
		}
	}
	return nil
}

// startRelay serves the TLS relay and describes it for the control plane:
// the hub's public host with the relay's port.
func startRelay(listen, staticEP string, wgPort int) (*relay.Server, *api.Relay, error) {
	host, _, err := net.SplitHostPort(staticEP)
	if err != nil {
		return nil, nil, err
	}
	srv, err := relay.Listen(listen, wgPort)
	if err != nil {
		return nil, nil, err
	}
	_, port, _ := net.SplitHostPort(srv.Addr().String())
	return srv, &api.Relay{Addr: net.JoinHostPort(host, port), Fingerprint: srv.Fingerprint}, nil
}

func netipCIDR(s string) netip.Prefix {
	p, _ := netip.ParsePrefix(s)
	return p
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// gatherCandidates asks STUN servers for WireGuard's public mapping and adds
// local interface addresses for peers on the same LAN. If two servers see
// different mapped ports the NAT is "symmetric" and direct punching will
// usually fail, leaving the hub as the path.
func gatherCandidates(ctx context.Context, dev *wg.Device, servers []string, port int, vpn netip.Prefix) (cands []string, public netip.Addr, nat string) {
	var mapped []netip.AddrPort
	for _, s := range servers {
		addr, err := resolveUDP4(ctx, s)
		if err != nil {
			continue
		}
		ap, err := dev.STUN(ctx, addr, 1500*time.Millisecond)
		if err != nil {
			continue
		}
		mapped = append(mapped, ap)
	}
	nat = "unknown"
	if len(mapped) > 0 {
		public = mapped[0].Addr()
		cands = append(cands, mapped[0].String())
		nat = "easy"
		for _, m := range mapped[1:] {
			if m != mapped[0] {
				nat = "symmetric (direct paths unlikely; using hub)"
			}
		}
		if localHas(mapped[0].Addr()) {
			nat = "none (public IP)"
		}
	}
	for _, a := range localAddrs(dev.Name, vpn) {
		ap := netip.AddrPortFrom(a, uint16(port)).String()
		if !slices.Contains(cands, ap) {
			cands = append(cands, ap)
		}
		if len(cands) >= 6 {
			break
		}
	}
	return cands, public, nat
}

func localHas(a netip.Addr) bool {
	for _, l := range localAddrs("", netip.Prefix{}) {
		if l == a {
			return true
		}
	}
	return false
}

// localAddrs lists usable IPv4 addresses on up, non-loopback interfaces,
// skipping our own tunnel and anything inside the VPN range.
func localAddrs(skipIface string, vpn netip.Prefix) []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Name == skipIface {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLinkLocalUnicast() || (vpn.IsValid() && vpn.Contains(ip)) {
				continue
			}
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Less(out[b]) })
	return out
}

func resolveUDP4(ctx context.Context, hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolving %s: %v", host, err)
	}
	pn, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(pn)), nil
}

// resolve turns peer endpoints into addresses; DNS names (static endpoints)
// are looked up, failures are skipped.
func resolve(ctx context.Context, peers []Peer) []ResolvedPeer {
	out := make([]ResolvedPeer, 0, len(peers))
	for _, p := range peers {
		rp := ResolvedPeer{Peer: p}
		for _, e := range p.Endpoints {
			if ap, err := resolveUDP4(ctx, e); err == nil && !slices.Contains(rp.Candidates, ap) {
				rp.Candidates = append(rp.Candidates, ap)
			}
		}
		out = append(out, rp)
	}
	return out
}
