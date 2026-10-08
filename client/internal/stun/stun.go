// Package stun implements the small part of STUN (RFC 8489) needed to learn
// this host's public address: Binding requests and XOR-MAPPED-ADDRESS.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

const (
	magicCookie      = 0x2112A442
	bindingRequest   = 0x0001
	bindingSuccess   = 0x0101
	attrMappedAddr   = 0x0001
	attrXorMapped    = 0x0020
	headerLen        = 20
	maxResponseBytes = 548
)

type TxID [12]byte

// IsSTUN reports whether b looks like a STUN message. WireGuard messages
// start with a type byte 1-4 followed by three zero bytes, so the magic cookie
// at offset 4 cleanly separates the two protocols sharing one UDP port.
func IsSTUN(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xC0 == 0 && binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

// Request builds a Binding request with a fresh random transaction ID.
func Request() (TxID, []byte) {
	var tx TxID
	_, _ = rand.Read(tx[:])
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return tx, b
}

// TxIDOf returns the transaction ID of a STUN message.
func TxIDOf(b []byte) (TxID, bool) {
	var tx TxID
	if !IsSTUN(b) {
		return tx, false
	}
	copy(tx[:], b[8:20])
	return tx, true
}

// ParseResponse extracts the mapped address from a Binding success response.
func ParseResponse(b []byte, want TxID) (netip.AddrPort, error) {
	if !IsSTUN(b) || len(b) > maxResponseBytes {
		return netip.AddrPort{}, errors.New("not a STUN message")
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingSuccess {
		return netip.AddrPort{}, errors.New("not a binding success response")
	}
	if TxID(b[8:20]) != want {
		return netip.AddrPort{}, errors.New("transaction ID mismatch")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+n > len(b) {
		return netip.AddrPort{}, errors.New("truncated STUN message")
	}
	attrs := b[headerLen : headerLen+n]
	var fallback netip.AddrPort
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		switch typ {
		case attrXorMapped:
			if ap, ok := parseAddr(v, true, b[4:20]); ok {
				return ap, nil
			}
		case attrMappedAddr:
			if ap, ok := parseAddr(v, false, nil); ok {
				fallback = ap
			}
		}
		pad := (4 - l%4) % 4
		if 4+l+pad > len(attrs) {
			break
		}
		attrs = attrs[4+l+pad:]
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.AddrPort{}, errors.New("no mapped address in response")
}

func parseAddr(v []byte, xor bool, key []byte) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	ip := make([]byte, 0, 16)
	switch v[1] {
	case 0x01:
		if len(v) != 8 {
			return netip.AddrPort{}, false
		}
		ip = append(ip, v[4:8]...)
	case 0x02:
		if len(v) != 20 {
			return netip.AddrPort{}, false
		}
		ip = append(ip, v[4:20]...)
	default:
		return netip.AddrPort{}, false
	}
	if xor {
		port ^= magicCookie >> 16
		for i := range ip {
			ip[i] ^= key[i]
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), port), true
}

// Response builds a Binding success response carrying XOR-MAPPED-ADDRESS.
// Used by the test STUN server.
func Response(req []byte, from netip.AddrPort) ([]byte, bool) {
	if !IsSTUN(req) || binary.BigEndian.Uint16(req[0:2]) != bindingRequest {
		return nil, false
	}
	ip := from.Addr().Unmap()
	family, raw := byte(0x01), ip.AsSlice()
	if ip.Is6() {
		family = 0x02
	}
	b := make([]byte, headerLen, headerLen+8+len(raw))
	binary.BigEndian.PutUint16(b[0:2], bindingSuccess)
	copy(b[4:20], req[4:20])
	v := make([]byte, 4+len(raw))
	v[1] = family
	binary.BigEndian.PutUint16(v[2:4], from.Port()^(magicCookie>>16))
	for i := range raw {
		v[4+i] = raw[i] ^ req[4+i]
	}
	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:2], attrXorMapped)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(v)))
	b = append(b, attr...)
	b = append(b, v...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-headerLen))
	return b, true
}

// Serve answers Binding requests on conn until it is closed.
func Serve(conn *net.UDPConn) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		if resp, ok := Response(buf[:n], from); ok {
			_, _ = conn.WriteToUDPAddrPort(resp, from)
		}
	}
}
