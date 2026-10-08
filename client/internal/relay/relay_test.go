package relay

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	if err := WriteFrame(&b, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxPacket)
	n, err := ReadFrame(&b, buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("got %q %v", buf[:n], err)
	}
	if WriteFrame(&b, make([]byte, MaxPacket+1)) == nil {
		t.Fatal("oversized frame accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0xff, 0xff}), buf); err == nil {
		t.Fatal("oversized frame read")
	}
}

func TestRelayRoundTripAndPinning(t *testing.T) {
	// Stand-in for the hub's WireGuard socket: echoes datagrams.
	wg, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := wg.ReadFromUDP(buf)
			if err != nil {
				return
			}
			wg.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	s, err := Listen("127.0.0.1:0", wg.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := Dial(s.Addr().String(), s.Fingerprint, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := WriteFrame(c, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, MaxPacket)
	n, err := ReadFrame(c, buf)
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("got %q %v", buf[:n], err)
	}

	wrong := "00" + s.Fingerprint[2:]
	if s.Fingerprint[:2] == "00" {
		wrong = "11" + s.Fingerprint[2:]
	}
	if _, err := Dial(s.Addr().String(), wrong, 2*time.Second); err == nil {
		t.Fatal("connected despite wrong fingerprint")
	}
}
