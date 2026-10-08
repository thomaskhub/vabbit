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
	Logf     func(format string, args ...any)
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
		stunCands  []netip.AddrPort // STUN-mapped addresses, at most one per family
		trans      transport
		hubs       = newHubPicker()
		lastHubKey string
		relaySrv   *relay.Server
		relayInfo  *api.Relay
	)
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
			var cands []string
			var public netip.Addr
			var nat string
			cands, stunCands, public, nat = gatherCandidates(ctx, dev, o.STUNServers, o.Device.ListenPort, netipCIDR(o.Device.NetworkCIDR))
			planner.MyPublic = public
			local := localAddrs(dev.Name, netipCIDR(o.Device.NetworkCIDR))
			planner.HaveV4, planner.HaveV6 = familiesOf(local)
			planner.LocalV6 = planner.LocalV6[:0]
			for _, a := range local {
				if !a.Is4() {
					planner.LocalV6 = append(planner.LocalV6, a)
				}
			}
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
				if n.Address != lastAddr || n.SelfHub != lastHub {
					if err := dev.SetAddress(n.Address); err != nil {
						return err
					}
					if err := applyForwarding(dev, n.SelfHub, o.Logf); err != nil {
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
				var target netip.AddrPort // the address the planner dials for the hub
				if hub != nil {
					hubStat = stats[hub.PublicKey]
					target = planner.HubTarget(*hub)
				}
				hasRelay := hub != nil && hub.Relay != nil && target.IsValid()
				if trans.step(now, hasRelay, hubStat, udpWorksTo(target, stunCands)) {
					trans.toggle(now)
					if trans.tcp {
						if err := dev.UseTCPRelay(target, hub.Relay.Addr, hub.Relay.Fingerprint); err != nil {
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
				} else if trans.tcp && hasRelay {
					// Follow the planner if the hub's address changed (no-op otherwise).
					if err := dev.UseTCPRelay(target, hub.Relay.Addr, hub.Relay.Fingerprint); err != nil {
						return err
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

// gatherCandidates asks STUN servers for WireGuard's public mapping (over IPv4 and over IPv6, where the
// host has that family) and adds local interface addresses for peers on the same LAN. If two servers see
// different mapped ports within one family the NAT is "symmetric" and direct punching will usually
// fail, leaving the hub as the path.
func gatherCandidates(ctx context.Context, dev *wg.Device, servers []string, port int, vpn netip.Prefix) (cands []string, stunCands []netip.AddrPort, public netip.Addr, nat string) {
	local := localAddrs(dev.Name, vpn)
	haveV4, haveV6 := familiesOf(local) // only ask over a family this host has an address for: no waiting on a dead one
	mapped := queryMapped(ctx, servers, haveV4, haveV6, lookupIP, func(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
		return dev.STUN(ctx, server, 1500*time.Millisecond)
	})
	stunCands, public, nat = summariseMapped(mapped, localHas)
	for _, ap := range stunCands {
		cands = append(cands, ap.String())
	}
	// Drop local addresses STUN already reported (public IP) before sharing out the room.
	var extra []netip.Addr
	for _, a := range local {
		if !slices.Contains(stunCands, netip.AddrPortFrom(a, uint16(port))) {
			extra = append(extra, a)
		}
	}
	for _, a := range limitLocal(extra, maxCandidates-len(cands)) {
		cands = append(cands, netip.AddrPortFrom(a, uint16(port)).String())
	}
	return cands, stunCands, public, nat
}

func localHas(a netip.Addr) bool {
	for _, l := range localAddrs("", netip.Prefix{}) {
		if l == a {
			return true
		}
	}
	return false
}

// localAddrs lists usable IPv4 and IPv6 addresses (global and unique-local, see usableLocal) on up,
// non-loopback interfaces, skipping our own tunnel and anything inside the VPN range. IPv4 comes first.
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
			if !usableLocal(ip, vpn) {
				continue
			}
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Less(out[b]) })
	return out
}

// resolve turns peer endpoints into addresses; DNS names (static endpoints)
// are looked up, failures are skipped.
func resolve(ctx context.Context, peers []Peer) []ResolvedPeer {
	out := make([]ResolvedPeer, 0, len(peers))
	for _, p := range peers {
		rp := ResolvedPeer{Peer: p}
		for _, e := range p.Endpoints {
			aps, err := resolveEndpoint(ctx, e, lookupIP)
			if err != nil {
				continue
			}
			for _, ap := range aps {
				if !slices.Contains(rp.Candidates, ap) {
					rp.Candidates = append(rp.Candidates, ap)
				}
			}
		}
		out = append(out, rp)
	}
	return out
}
