//go:build darwin

package wg

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
)

// The interface is a utun device whose number the kernel picks; vabbit keeps
// calling it by its own name (vb0), which names the control socket, the state
// file and the launchd service.

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// ValidIface reports whether name is a safe interface name.
func ValidIface(name string) bool { return ifaceRE.MatchString(name) }

// ErrHubUnsupported is returned when a Mac is asked to be a hub.
var ErrHubUnsupported = errors.New("a hub must run Linux for now; Macs can only be ordinary devices")

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// SetAddress assigns the VPN address to the utun interface (point-to-point,
// to itself) and routes the whole network into it.
func (d *Device) SetAddress(addr netip.Prefix) error {
	d.mu.Lock()
	old := d.addr
	d.mu.Unlock()
	if old.IsValid() && old != addr {
		_ = run("ifconfig", d.ifname, "inet", old.Addr().String(), "-alias")
		_ = run("route", "-q", "-n", "delete", "-inet", old.Masked().String(), "-interface", d.ifname)
	}
	a := addr.Addr().String()
	if err := run("ifconfig", d.ifname, "inet", a, a, "netmask", "255.255.255.255",
		"mtu", fmt.Sprint(MTU), "up"); err != nil {
		return err
	}
	_ = run("route", "-q", "-n", "delete", "-inet", addr.Masked().String(), "-interface", d.ifname)
	if err := run("route", "-q", "-n", "add", "-inet", addr.Masked().String(), "-interface", d.ifname); err != nil {
		return err
	}
	d.mu.Lock()
	d.addr = addr
	d.mu.Unlock()
	return nil
}

// SetForwarding refuses to make a Mac a hub. Off needs nothing: macOS only
// forwards with the system-wide net.inet.ip.forwarding (Internet Sharing),
// and peers only send a non-hub packets for its own address.
func (d *Device) SetForwarding(on bool) error {
	if on {
		return ErrHubUnsupported
	}
	return nil
}

// Forwarding reports false: see SetForwarding.
func (d *Device) Forwarding() (bool, error) { return false, nil }

// AllowInbound is a no-op: the macOS application firewall is left to the user.
func (d *Device) AllowInbound(netip.Prefix, int) error { return nil }

// RemoveInbound is a no-op on macOS.
func RemoveInbound(string) {}

// serveUAPI exposes the WireGuard control socket under vabbit's name for the
// interface (root only), so `vabbit status` works. Failure is not fatal.
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

func sockPath(name string) string { return "/var/run/wireguard/" + name + ".sock" }

// Show reads live state of a running interface from its control socket.
func Show(name string) (map[string]PeerStat, error) {
	if !ValidIface(name) {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	c, err := net.Dial("unix", sockPath(name))
	if err != nil {
		return nil, fmt.Errorf("interface %s is not running", name)
	}
	defer c.Close()
	return queryStats(c, name)
}

// ServiceLabel is the launchd service that runs `vabbit up` for an interface.
func ServiceLabel(iface string) string { return "com.vabbit." + iface }

// ServicePlist is where that service's definition lives.
func ServicePlist(iface string) string {
	return "/Library/LaunchDaemons/" + ServiceLabel(iface) + ".plist"
}

// Down stops the agent that owns the interface; the utun device goes away with
// it. A launchd service is unloaded (it stays installed and starts again at
// boot); an agent in a terminal is asked to stop.
func Down(name string) error {
	if !ValidIface(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	if _, err := os.Stat(ServicePlist(name)); err == nil {
		_ = run("launchctl", "bootout", "system/"+ServiceLabel(name))
	} else if pid := socketOwner(name); pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	for i := 0; i < 40; i++ {
		if _, err := Show(name); err != nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("%s did not stop", name)
}

// socketOwner returns the process that serves the control socket of name, or 0.
func socketOwner(name string) int {
	c, err := net.Dial("unix", sockPath(name))
	if err != nil {
		return 0
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	raw.Control(func(fd uintptr) {
		// LOCAL_PEERPID on the socket's own level (SOL_LOCAL = 0).
		if v, err := syscall.GetsockoptInt(int(fd), 0, 0x002); err == nil {
			pid = v
		}
	})
	return pid
}
