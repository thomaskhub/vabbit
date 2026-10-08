package stun

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.7:40000", "[2001:db8::5]:1"} {
		tx, req := Request()
		if !IsSTUN(req) {
			t.Fatal("request not recognised")
		}
		want := netip.MustParseAddrPort(s)
		resp, ok := Response(req, want)
		if !ok {
			t.Fatal("no response")
		}
		got, err := ParseResponse(resp, tx)
		if err != nil || got != want {
			t.Fatalf("got %v %v want %v", got, err, want)
		}
		var other TxID
		if _, err := ParseResponse(resp, other); err == nil {
			t.Fatal("accepted wrong transaction ID")
		}
	}
}

// RFC 5769 section 2.2 IPv4 response vector (fingerprint/integrity ignored).
func TestRFC5769(t *testing.T) {
	b, _ := hex.DecodeString("0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220" +
		"002000080001a147e112a643000800149ae4d3c6b3e3bf3f9b17c13bfde8b05c1fa1af4c" +
		"80280004c07d4c96")
	var tx TxID
	copy(tx[:], b[8:20])
	got, err := ParseResponse(b, tx)
	if err != nil || got != netip.MustParseAddrPort("192.0.2.1:32853") {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestWireGuardIsNotSTUN(t *testing.T) {
	for typ := byte(1); typ <= 4; typ++ {
		b := make([]byte, 148)
		b[0] = typ
		if IsSTUN(b) {
			t.Fatalf("WireGuard type %d classified as STUN", typ)
		}
	}
}

func FuzzParse(f *testing.F) {
	_, req := Request()
	resp, _ := Response(req, netip.MustParseAddrPort("1.2.3.4:5"))
	f.Add(resp)
	f.Fuzz(func(t *testing.T, b []byte) {
		var tx TxID
		if len(b) >= 20 {
			copy(tx[:], b[8:20])
		}
		_, _ = ParseResponse(b, tx)
	})
}
