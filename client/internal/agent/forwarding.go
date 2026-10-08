package agent

import "fmt"

// forwardingSetter is the part of the tunnel interface that applyForwarding needs.
type forwardingSetter interface {
	SetForwarding(on bool) error
	Forwarding() (bool, error)
}

// applyForwarding sets IPv4 forwarding on the tunnel interface: on for a hub, off for everyone else.
// A hub must be able to route between peers, so a failure is fatal there. A device that is not a hub
// only wants forwarding off; where the setting cannot be written (read-only /proc/sys in an
// unprivileged container) the tunnel still comes up if forwarding is already off. If it is on (the
// host forwards, e.g. Docker sets ip_forward=1) or unknown, the device would route traffic for peers
// like a hub the admin never approved, so that is fatal too.
func applyForwarding(d forwardingSetter, hub bool, logf func(format string, args ...any)) error {
	err := d.SetForwarding(hub)
	if err == nil {
		return nil
	}
	if hub {
		return fmt.Errorf("a hub needs IP forwarding: %w", err)
	}
	on, rerr := d.Forwarding()
	switch {
	case rerr != nil:
		return fmt.Errorf("could not turn IP forwarding off on the tunnel interface (%w) or read it (%v)", err, rerr)
	case on:
		return fmt.Errorf("IP forwarding is on for the tunnel interface and could not be turned off (%w); "+
			"turn off net.ipv4.ip_forward or give the agent write access to /proc/sys/net/ipv4/conf", err)
	}
	logf("could not write the IP forwarding setting on the tunnel interface (%v); it is already off", err)
	return nil
}
