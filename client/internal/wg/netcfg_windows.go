//go:build windows

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
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// The interface is a Wintun adapter; wintun.dll must sit next to vabbit.exe.

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// ValidIface reports whether name is a safe adapter name.
func ValidIface(name string) bool { return ifaceRE.MatchString(name) }

// ErrHubUnsupported is returned when a Windows device is asked to be a hub.
var ErrHubUnsupported = errors.New("a hub must run Linux for now; Windows devices can only be ordinary devices")

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// SetAddress assigns the VPN address with the network's mask (which also
// adds the on-link route for the whole network) and sets the MTU.
func (d *Device) SetAddress(addr netip.Prefix) error {
	mask := net.IP(net.CIDRMask(addr.Bits(), 32)).String()
	var err error
	// A new Wintun adapter takes a moment to show up for netsh.
	for i := 0; i < 20; i++ {
		if err = run("netsh", "interface", "ipv4", "set", "address", "name="+d.Name, "source=static",
			"address="+addr.Addr().String(), "mask="+mask); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	return run("netsh", "interface", "ipv4", "set", "subinterface", d.Name, fmt.Sprintf("mtu=%d", MTU), "store=active")
}

// SetForwarding turns IPv4 forwarding off on the adapter. Hubs are Linux-only.
func (d *Device) SetForwarding(on bool) error {
	if on {
		return ErrHubUnsupported
	}
	return run("netsh", "interface", "ipv4", "set", "interface", d.Name, "forwarding=disabled")
}

// Forwarding reports whether IPv4 forwarding is on for the adapter.
func (d *Device) Forwarding() (bool, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetIPInterface -InterfaceAlias '"+d.Name+"' -AddressFamily IPv4).Forwarding").Output()
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "Disabled":
		return false, nil
	case "Enabled":
		return true, nil
	}
	return false, fmt.Errorf("unexpected forwarding state %q", strings.TrimSpace(string(out)))
}

// AllowInbound adds Windows Firewall rules for this interface: WireGuard's
// UDP port (for direct connections) and ping from inside the VPN. Anything
// else arriving through the VPN stays subject to the normal firewall rules.
func (d *Device) AllowInbound(network netip.Prefix, port int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	RemoveInbound(d.Name)
	if err := run("netsh", "advfirewall", "firewall", "add", "rule", "name=Vabbit "+d.Name+" WireGuard",
		"dir=in", "action=allow", "protocol=UDP", fmt.Sprintf("localport=%d", port), "program="+exe); err != nil {
		return err
	}
	return run("netsh", "advfirewall", "firewall", "add", "rule", "name=Vabbit "+d.Name+" ping",
		"dir=in", "action=allow", "protocol=icmpv4:8,any", "localip="+network.String())
}

// RemoveInbound deletes the firewall rules AllowInbound added.
func RemoveInbound(name string) {
	for _, r := range []string{"WireGuard", "ping"} {
		_ = run("netsh", "advfirewall", "firewall", "delete", "rule", "name=Vabbit "+name+" "+r)
	}
}

const pipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`

// serveUAPI exposes the standard WireGuard control pipe (Administrators
// only) so `vabbit status` works. Failure is not fatal.
func serveUAPI(name string, dev *device.Device) func() {
	l, err := ipc.UAPIListen(name)
	if err != nil {
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

// Show reads live state of a running interface from its control pipe.
func Show(name string) (map[string]PeerStat, error) {
	if !ValidIface(name) {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	c, err := namedpipe.DialTimeout(pipePrefix+name, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("interface %s is not running", name)
	}
	defer c.Close()
	return queryStats(c, name)
}

// ServiceName is the Windows service that runs `vabbit up` for an interface.
func ServiceName(iface string) string { return "vabbit-" + iface }

// Down stops the service that owns the interface; the adapter goes away with it.
func Down(name string) error {
	if !ValidIface(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName(name))
	if err != nil {
		if _, serr := Show(name); serr == nil {
			return fmt.Errorf("%s is running in a terminal, not as a service: stop it with Ctrl-C", name)
		}
		return nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return err
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	for i := 0; i < 40; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service %s did not stop", ServiceName(name))
}
