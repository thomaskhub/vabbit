// Command stunserver is a minimal STUN server for local NAT traversal tests.
package main

import (
	"flag"
	"log"
	"net"

	"vabbit/internal/stun"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:3478", "UDP address to listen on")
	flag.Parse()
	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("STUN on %s", c.LocalAddr())
	log.Fatal(stun.Serve(c))
}
