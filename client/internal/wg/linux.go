//go:build linux

package wg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// ValidIface reports whether name is a safe Linux interface name.
func ValidIface(name string) bool { return ifaceRE.MatchString(name) }

func run(stdin string, name string, args ...string) error {
	return runEnv(nil, stdin, name, args...)
}

func runEnv(env []string, stdin string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func linkExists(iface string) bool {
	_, err := os.Stat("/sys/class/net/" + iface)
	return err == nil
}

// Apply creates the interface if needed and converges it to the desired state.
// It requires root (CAP_NET_ADMIN), the wireguard kernel module, `ip` and `wg`.
func Apply(iface string, cfg Interface, forward bool) error {
	if !ValidIface(iface) {
		return fmt.Errorf("invalid interface name %q", iface)
	}
	if !linkExists(iface) {
		if err := run("", "ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
			// No kernel module (e.g. containers): fall back to userspace wireguard-go.
			if _, lerr := exec.LookPath("wireguard-go"); lerr != nil {
				return fmt.Errorf("creating interface (no wireguard kernel module and no wireguard-go): %w", err)
			}
			// The kernel refused the link type, so wireguard-go's "kernel has
			// WireGuard" check is a false positive here.
			env := []string{"WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1"}
			if err := runEnv(env, "", "wireguard-go", iface); err != nil {
				return err
			}
		}
	}
	// The private key is passed on stdin, never on the command line or disk.
	if err := run(cfg.Render(), "wg", "syncconf", iface, "/dev/stdin"); err != nil {
		return err
	}
	if err := run("", "ip", "-4", "address", "replace", cfg.Address.String(), "dev", iface); err != nil {
		return err
	}
	if err := run("", "ip", "link", "set", "dev", iface, "mtu", "1380", "up"); err != nil {
		return err
	}
	val := "0"
	if forward {
		val = "1"
	}
	return os.WriteFile("/proc/sys/net/ipv4/conf/"+iface+"/forwarding", []byte(val), 0o644)
}

// Down removes the interface. It is not an error if it does not exist.
func Down(iface string) error {
	if !ValidIface(iface) {
		return fmt.Errorf("invalid interface name %q", iface)
	}
	if !linkExists(iface) {
		return nil
	}
	return run("", "ip", "link", "del", "dev", iface)
}

// Show returns `wg show <iface>` output.
func Show(iface string) (string, error) {
	if !ValidIface(iface) {
		return "", fmt.Errorf("invalid interface name %q", iface)
	}
	out, err := exec.Command("wg", "show", iface).CombinedOutput()
	return string(out), err
}
