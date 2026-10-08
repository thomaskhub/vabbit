package agent

import (
	"net/netip"
	"slices"
	"testing"

	"vabbit/internal/hosts"
)

func e(addr, name string) hosts.Entry {
	return hosts.Entry{Addr: netip.MustParseAddr(addr), Name: name}
}

func peerList(ps ...Peer) []Peer { return ps }

func TestHostEntries(t *testing.T) {
	self := netip.MustParseAddr("100.92.0.1")
	got, skipped := hostEntries("me", self, peerList(
		Peer{Name: "db", IP: netip.MustParseAddr("100.92.0.2")},
		Peer{Name: "Web-1", IP: netip.MustParseAddr("100.92.0.3")},  // lower-cased
		Peer{Name: "my_box", IP: netip.MustParseAddr("100.92.0.4")}, // not a host name
		Peer{Name: "a?b", IP: netip.MustParseAddr("100.92.0.5")},    // sanitised by the client, still invalid
		Peer{Name: "me", IP: netip.MustParseAddr("100.92.0.6")},     // our own name: we win
		Peer{Name: "db", IP: netip.MustParseAddr("100.92.0.7")},     // same name twice: the first stays
		Peer{Name: "github.com", IP: netip.MustParseAddr("100.92.0.8")},
	), "vabbit")
	want := []hosts.Entry{
		e("100.92.0.1", "me.vabbit"),
		e("100.92.0.2", "db.vabbit"),
		e("100.92.0.3", "web-1.vabbit"),
		e("100.92.0.8", "github.com.vabbit"), // qualified, so it cannot shadow github.com
	}
	if !slices.Equal(got, want) {
		t.Errorf("entries =\n %v\nwant\n %v", got, want)
	}
	if skipped != 4 {
		t.Errorf("skipped = %d, want 4 (two invalid names, one that is ours, one second db)", skipped)
	}
}

func TestHostEntriesNeverWriteShortNames(t *testing.T) {
	got, _ := hostEntries("me", netip.MustParseAddr("100.92.0.1"), peerList(Peer{Name: "localhost", IP: netip.MustParseAddr("100.92.0.2")}), "vabbit")
	for _, en := range got {
		if en.Name == "localhost" || en.Name == "me" {
			t.Errorf("short name written: %v", en)
		}
	}
}

func TestHostEntriesOff(t *testing.T) {
	if got, _ := hostEntries("me", netip.MustParseAddr("100.92.0.1"), nil, ""); got != nil {
		t.Errorf("an empty domain turns the feature off, got %v", got)
	}
}

func TestEffectiveDomain(t *testing.T) {
	for _, tc := range []struct {
		stored, want string
		ok           bool
	}{
		{"", "vabbit", true},
		{"vabbit", "vabbit", true},
		{"vpn.example.com", "vpn.example.com", true},
		{"none", "", true},
		{"Bad_Domain", "", false},
		{"com", "", false},
		{"local", "", false},
		{"lan", "", false},
		{"corp", "corp", true},
	} {
		got, err := EffectiveDomain(tc.stored)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("EffectiveDomain(%q) = %q, %v; want %q ok=%v", tc.stored, got, err, tc.want, tc.ok)
		}
	}
}
