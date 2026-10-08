package wg

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"edgeguard/internal/api"
)

func TestPublicKeyRFC7748(t *testing.T) {
	priv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	got, err := PublicKey(base64.StdEncoding.EncodeToString(priv))
	if err != nil || got != base64.StdEncoding.EncodeToString(want) {
		t.Fatalf("got %s %v", got, err)
	}
}

func TestGenerateKey(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := base64.StdEncoding.DecodeString(priv)
	if b[0]&7 != 0 || b[31]&128 != 0 || b[31]&64 == 0 {
		t.Fatal("key not clamped")
	}
	if p, _ := PublicKey(priv); p != pub {
		t.Fatal("public key mismatch")
	}
}

const k1 = "Ag3x3mJ0bWg3J7Ff2x7bX9H1t2Y8l9l3v0QkzQ9dQ3w="

func sync(peers ...api.Peer) api.SyncResponse {
	return api.SyncResponse{Network: api.Network{CIDR: "100.92.0.0/16"}, Address: "100.92.0.5/16", Peers: peers}
}

func TestFromSyncRenders(t *testing.T) {
	cfg, err := FromSync(sync(
		api.Peer{PublicKey: k1, AllowedIPs: []string{"100.92.0.0/16"}, Endpoint: "203.0.113.1:51820", PersistentKeepalive: 25},
	), "100.92.0.0/16", k1, 51820)
	if err != nil {
		t.Fatal(err)
	}
	want := "[Interface]\nPrivateKey = " + k1 + "\nListenPort = 51820\n\n[Peer]\nPublicKey = " + k1 +
		"\nAllowedIPs = 100.92.0.0/16\nEndpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\n"
	if got := cfg.Render(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestFromSyncRejectsHostileData(t *testing.T) {
	cases := map[string]api.SyncResponse{
		"default route":      sync(api.Peer{PublicKey: k1, AllowedIPs: []string{"0.0.0.0/0"}}),
		"outside network":    sync(api.Peer{PublicKey: k1, AllowedIPs: []string{"10.0.0.1/32"}}),
		"unmasked prefix":    sync(api.Peer{PublicKey: k1, AllowedIPs: []string{"100.92.0.1/16"}}),
		"config injection":   sync(api.Peer{PublicKey: k1 + "\n[Peer]", AllowedIPs: []string{"100.92.0.1/32"}}),
		"endpoint injection": sync(api.Peer{PublicKey: k1, AllowedIPs: []string{"100.92.0.1/32"}, Endpoint: "1.2.3.4:1\nAllowedIPs = 0.0.0.0/0"}),
		"no allowed ips":     sync(api.Peer{PublicKey: k1}),
		"duplicate peer":     sync(api.Peer{PublicKey: k1, AllowedIPs: []string{"100.92.0.1/32"}}, api.Peer{PublicKey: k1, AllowedIPs: []string{"100.92.0.2/32"}}),
	}
	bad := sync()
	bad.Network.CIDR = "0.0.0.0/0"
	cases["cidr changed"] = bad
	bad2 := sync()
	bad2.Address = "8.8.8.8/16"
	cases["address outside"] = bad2
	for name, s := range cases {
		if _, err := FromSync(s, "100.92.0.0/16", k1, 51820); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateEndpoint(t *testing.T) {
	for _, ok := range []string{"1.2.3.4:51820", "[2001:db8::1]:1", "vpn.example.com:443"} {
		if err := ValidateEndpoint(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"1.2.3.4", "a:0", "a b:1", "-a:1", strings.Repeat("a", 64) + ".com:1"} {
		if ValidateEndpoint(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
