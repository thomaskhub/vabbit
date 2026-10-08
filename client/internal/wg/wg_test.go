package wg

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
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

func TestParseStats(t *testing.T) {
	k := hex.EncodeToString(make([]byte, 32))
	s := "private_key=" + k + "\nlisten_port=51820\npublic_key=" + k +
		"\nendpoint=1.2.3.4:5\nlast_handshake_time_sec=1700000000\nrx_bytes=10\ntx_bytes=20\npersistent_keepalive_interval=25\nerrno=0\n"
	st := ParseStats(s)
	p, ok := st[base64.StdEncoding.EncodeToString(make([]byte, 32))]
	if !ok || p.Endpoint.String() != "1.2.3.4:5" || p.LastHandshake.Unix() != 1700000000 || p.RxBytes != 10 || p.TxBytes != 20 {
		t.Fatalf("got %+v", st)
	}
}
