//go:build linux

package wg

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
)

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// ValidIface reports whether name is a safe Linux interface name.
func ValidIface(name string) bool { return ifaceRE.MatchString(name) }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// SetAddress assigns the VPN address (with the network prefix length, which
// also installs the route for the whole network) and brings the link up.
func (d *Device) SetAddress(addr netip.Prefix) error {
	if err := run("ip", "-4", "address", "replace", addr.String(), "dev", d.Name); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", d.Name, "mtu", fmt.Sprint(MTU), "up")
}

// SetForwarding lets a hub route packets between peers on this interface only.
func (d *Device) SetForwarding(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile("/proc/sys/net/ipv4/conf/"+d.Name+"/forwarding", []byte(v), 0o644)
}

// serveUAPI exposes the standard WireGuard control socket (root only) so
// `wg show` and `edgeguard status` work. Failure is not fatal.
func serveUAPI(name string, dev *device.Device) func() {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil
	}
	l, err := ipc.UAPIListen(name, f)
	if err != nil {
		f.Close()
		return nil
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()
	return func() { l.Close() }
}

// Show reads live state of a running interface from its control socket.
func Show(name string) (map[string]PeerStat, error) {
	if !ValidIface(name) {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	c, err := net.Dial("unix", "/var/run/wireguard/"+name+".sock")
	if err != nil {
		return nil, fmt.Errorf("interface %s is not running", name)
	}
	defer c.Close()
	if _, err := c.Write([]byte("get=1\n\n")); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// The socket stays open for more requests; a reply ends with "errno=N" and a blank line.
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

// Down deletes the interface, which also stops the agent that owns it.
func Down(name string) error {
	if !ValidIface(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	if _, err := os.Stat("/sys/class/net/" + name); err != nil {
		return nil
	}
	return run("ip", "link", "del", "dev", name)
}
