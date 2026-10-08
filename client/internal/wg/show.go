package wg

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// queryStats asks a WireGuard control socket for its state. The socket stays
// open for more requests; a reply ends with "errno=N" and a blank line.
func queryStats(c net.Conn, name string) (map[string]PeerStat, error) {
	if _, err := c.Write([]byte("get=1\n\n")); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	sc := bufio.NewScanner(io.LimitReader(c, 1<<20))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "errno=") && line != "errno=0" {
			return nil, fmt.Errorf("interface %s: %s", name, line)
		}
		b.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ParseStats(b.String()), nil
}
