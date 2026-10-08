// Package relay carries WireGuard datagrams over TLS on TCP, for networks that
// block UDP (hotels, some corporate Wi-Fi). It runs on the hub.
//
// The stream is just length-prefixed WireGuard packets. TLS makes it look like
// HTTPS on port 443 and hides the WireGuard framing; it adds no trust: the
// client pins the hub's certificate fingerprint, which it gets from the control
// plane, and WireGuard authenticates and encrypts everything inside anyway.
package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"
)

// MaxPacket is larger than any WireGuard packet at our MTU.
const MaxPacket = 2048

// WriteFrame writes one packet with a 2-byte big-endian length prefix.
func WriteFrame(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > MaxPacket {
		return fmt.Errorf("bad packet size %d", len(p))
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one packet into buf and returns its length.
func ReadFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > MaxPacket || n > len(buf) {
		return 0, fmt.Errorf("bad frame size %d", n)
	}
	_, err := io.ReadFull(r, buf[:n])
	return n, err
}

// Server accepts TLS connections and forwards their packets to the local
// WireGuard port, one UDP socket per connection so replies find their way back.
type Server struct {
	Fingerprint string // hex SHA-256 of the certificate, published to clients
	ln          net.Listener
	wgAddr      *net.UDPAddr
	sem         chan struct{}
	wg          sync.WaitGroup
}

const maxConns = 128

// Listen starts a relay on addr (e.g. ":443") for the WireGuard port wgPort.
func Listen(addr string, wgPort int) (*Server, error) {
	cert, fp, err := selfSigned()
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return nil, err
	}
	s := &Server{
		Fingerprint: fp,
		ln:          ln,
		wgAddr:      &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort},
		sem:         make(chan struct{}, maxConns),
	}
	go s.serve()
	return s, nil
}

func (s *Server) Addr() net.Addr { return s.ln.Addr() }

func (s *Server) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		default:
			c.Close() // at capacity
			continue
		}
		s.wg.Add(1)
		go func() {
			defer func() { <-s.sem; s.wg.Done() }()
			s.handle(c)
		}()
	}
}

const idleTimeout = 2 * time.Minute // WireGuard keepalives arrive every 25s

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	u, err := net.DialUDP("udp4", nil, s.wgAddr)
	if err != nil {
		return
	}
	defer u.Close()
	done := make(chan struct{})
	go func() { // WireGuard -> client
		defer close(done)
		buf := make([]byte, MaxPacket)
		for {
			_ = u.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := u.Read(buf)
			if err != nil {
				c.Close()
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if WriteFrame(c, buf[:n]) != nil {
				return
			}
		}
	}()
	buf := make([]byte, MaxPacket)
	for { // client -> WireGuard
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := ReadFrame(c, buf)
		if err != nil {
			break
		}
		if _, err := u.Write(buf[:n]); err != nil {
			break
		}
	}
	u.Close()
	<-done
}

func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vabbit-relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// Dial connects to a relay and verifies its certificate against the pinned
// fingerprint instead of a CA (the hub's certificate is self-signed).
func Dial(addr, fingerprint string, timeout time.Duration) (net.Conn, error) {
	want, err := hex.DecodeString(fingerprint)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("invalid relay fingerprint")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Chain verification is replaced by the pin below.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("relay sent no certificate")
			}
			got := sha256.Sum256(raw[0])
			if string(got[:]) != string(want) {
				return errors.New("relay certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
	d := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

// ValidAddr reports whether s is a usable relay address (IP:port).
func ValidAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Port() != 0
}
