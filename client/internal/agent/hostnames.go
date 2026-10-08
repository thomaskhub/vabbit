package agent

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"vabbit/internal/hosts"
)

// DefaultDomain is the domain under which device names are written to the hosts file.
const DefaultDomain = "vabbit"

// reservedDomains are single-label domains that already mean something (public TLDs, mDNS, the
// loopback name, common home-router domains): names under them would shadow real hosts.
var reservedDomains = []string{"com", "net", "org", "local", "localhost", "internal", "lan", "home", "arpa"}

// EffectiveDomain turns the stored setting into the domain to use: "" is the default, "none" switches
// the hosts-file entries off (empty result), anything else must be a valid DNS name and not one of
// reservedDomains.
func EffectiveDomain(stored string) (string, error) {
	switch stored {
	case "":
		return DefaultDomain, nil
	case "none":
		return "", nil
	}
	if !hosts.ValidDomain(stored) {
		return "", fmt.Errorf("invalid domain %q: use lower-case letters, digits, hyphens and dots, or \"none\"", stored)
	}
	if slices.Contains(reservedDomains, stored) {
		return "", fmt.Errorf("domain %q is already in use elsewhere: choose your own, e.g. vpn.example.com", stored)
	}
	return stored, nil
}

// hostEntries builds the hosts-file entries for this device and its peers: "<name>.<domain>" only,
// never the short name, because a device chooses its own name and a short name would let it shadow
// names on this machine. Names that are not valid host names are skipped; this device's own name wins
// over a peer with the same name, and of several peers with one name the first stays. An empty domain
// means the feature is off.
func hostEntries(selfName string, selfAddr netip.Addr, peers []Peer, domain string) (entries []hosts.Entry, skipped int) {
	if domain == "" {
		return nil, 0
	}
	seen := map[string]bool{}
	add := func(name string, addr netip.Addr) {
		name = strings.ToLower(name)
		fqdn := name + "." + domain
		if !hosts.ValidHostName(name) || seen[fqdn] {
			skipped++
			return
		}
		seen[fqdn] = true
		entries = append(entries, hosts.Entry{Addr: addr, Name: fqdn})
	}
	add(selfName, selfAddr)
	for _, p := range peers {
		add(p.Name, p.IP)
	}
	return entries, skipped
}
