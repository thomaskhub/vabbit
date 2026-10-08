package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	// maxCandidates is how many endpoint candidates a device publishes in total.
	maxCandidates = 6
	// maxResolved is how many addresses one host name may contribute.
	maxResolved  = 4
	symmetricNAT = "symmetric (direct paths unlikely; using hub)"
)

// usableLocal reports whether an interface address may be offered to peers: unicast, not loopback,
// not link-local, not inside the VPN. IPv6 unique-local (fc00::/7) and global addresses qualify.
func usableLocal(ip netip.Addr, vpn netip.Prefix) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsLoopback(), ip.IsMulticast(), ip.IsLinkLocalUnicast():
		return false
	case vpn.IsValid() && vpn.Contains(ip):
		return false
	}
	return true
}

// limitLocal keeps at most room addresses. When it has to cut, the two families share the room
// (IPv4, IPv6, IPv4, ...). With one family only, the first room addresses stay in order.
func limitLocal(addrs []netip.Addr, room int) []netip.Addr {
	if room <= 0 {
		return nil
	}
	if len(addrs) <= room {
		return addrs
	}
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	out := make([]netip.Addr, 0, room)
	for i := 0; len(out) < room && (i < len(v4) || i < len(v6)); i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if i < len(v6) && len(out) < room {
			out = append(out, v6[i])
		}
	}
	return out
}

// familiesOf reports whether addrs holds an IPv4 and an IPv6 address.
func familiesOf(addrs []netip.Addr) (v4, v6 bool) {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4, v6
}

// filterFamilies drops the candidates of a family this host has no address for. Both false means the
// families are unknown: nothing is dropped. It never returns an empty list for a non-empty input.
func filterFamilies(c []netip.AddrPort, haveV4, haveV6 bool) []netip.AddrPort {
	if !haveV4 && !haveV6 {
		return c
	}
	out := make([]netip.AddrPort, 0, len(c))
	for _, a := range c {
		if a.Addr().Unmap().Is4() && haveV4 || !a.Addr().Unmap().Is4() && haveV6 {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return c
	}
	return out
}

// summariseMapped turns the STUN answers (any number of servers, both families) into candidates: the
// first mapped address of each family, IPv4 first. The NAT is symmetric when two servers disagree
// within a family, and "none (public IP)" when every mapped address is one of our own.
func summariseMapped(mapped []netip.AddrPort, isLocal func(netip.Addr) bool) (cands []netip.AddrPort, public netip.Addr, nat string) {
	nat = "unknown"
	if len(mapped) == 0 {
		return nil, netip.Addr{}, nat
	}
	var first4, first6 netip.AddrPort
	symmetric, allLocal := false, true
	for _, m := range mapped {
		first := &first6
		if m.Addr().Is4() {
			first = &first4
		}
		if !first.IsValid() {
			*first = m
			allLocal = allLocal && isLocal(m.Addr())
		} else if m != *first {
			symmetric = true
		}
	}
	for _, f := range []netip.AddrPort{first4, first6} {
		if f.IsValid() {
			cands = append(cands, f)
		}
	}
	public = cands[0].Addr()
	switch {
	case allLocal:
		nat = "none (public IP)"
	case symmetric:
		nat = symmetricNAT
	default:
		nat = "easy"
	}
	return cands, public, nat
}

// stunQuery asks one STUN server for our mapped address.
type stunQuery func(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error)

// queryMapped asks every server, over each family this host has (see filterFamilies), for our mapped
// address. All lookups and queries run at once, so a dead family or server costs one timeout, not one
// per query. The answers keep the servers' order, IPv4 before IPv6 within a server.
func queryMapped(ctx context.Context, servers []string, haveV4, haveV6 bool, lookup lookupFunc, query stunQuery) []netip.AddrPort {
	results := make([][2]netip.AddrPort, len(servers))
	var all sync.WaitGroup
	for i, s := range servers {
		all.Add(1)
		go func() {
			defer all.Done()
			addrs, err := resolveEndpoint(ctx, s, lookup)
			if err != nil {
				return
			}
			var inner sync.WaitGroup
			for j, addr := range firstPerFamily(filterFamilies(addrs, haveV4, haveV6)) {
				inner.Add(1)
				go func() {
					defer inner.Done()
					if ap, err := query(ctx, addr); err == nil { // an error is e.g. no route for that family
						results[i][j] = ap
					}
				}()
			}
			inner.Wait()
		}()
	}
	all.Wait()
	var mapped []netip.AddrPort
	for _, r := range results {
		for _, ap := range r {
			if ap.IsValid() {
				mapped = append(mapped, ap)
			}
		}
	}
	return mapped
}

// udpWorksTo reports whether STUN got an answer over the family of target, the address we use for the
// hub. With no target, an answer over either family counts.
func udpWorksTo(target netip.AddrPort, stunCands []netip.AddrPort) bool {
	for _, c := range stunCands {
		if !target.IsValid() || c.Addr().Unmap().Is4() == target.Addr().Unmap().Is4() {
			return true
		}
	}
	return false
}

// firstPerFamily returns the first IPv4 and the first IPv6 address of the list (IPv4 first).
func firstPerFamily(aps []netip.AddrPort) []netip.AddrPort {
	var v4, v6 netip.AddrPort
	for _, a := range aps {
		switch {
		case a.Addr().Unmap().Is4() && !v4.IsValid():
			v4 = a
		case !a.Addr().Unmap().Is4() && !v6.IsValid():
			v6 = a
		}
	}
	var out []netip.AddrPort
	for _, a := range []netip.AddrPort{v4, v6} {
		if a.IsValid() {
			out = append(out, a)
		}
	}
	return out
}

// lookupFunc resolves a host name to its IPv4 and IPv6 addresses.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveEndpoint turns "host:port" into addresses of both families, IPv4 first, at most maxResolved.
// A literal address is returned as it is. On an IPv6-only host behind DNS64 a name that only has an
// IPv4 address resolves to a synthesized IPv6 address, which is what makes it reachable.
func resolveEndpoint(ctx context.Context, hostport string, lookup lookupFunc) ([]netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return []netip.AddrPort{ap}, nil
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	pn, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolving %s: %v", host, err)
	}
	var v4, v6 []netip.AddrPort
	for _, ip := range ips {
		ap := netip.AddrPortFrom(ip.Unmap(), uint16(pn))
		switch {
		case slices.Contains(v4, ap) || slices.Contains(v6, ap):
		case ap.Addr().Is4():
			v4 = append(v4, ap)
		default:
			v6 = append(v6, ap)
		}
	}
	out := append(v4, v6...)
	if len(out) > maxResolved {
		out = out[:maxResolved]
	}
	return out, nil
}
