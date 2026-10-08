package agent

import "fmt"

// forwardingSetter is the part of the tunnel interface that applyForwarding needs.
type forwardingSetter interface {
	SetForwarding(on bool) error
}

// applyForwarding sets IPv4 forwarding on the tunnel interface: on for a hub, off for everyone else.
// A hub must be able to route between peers, so a failure is fatal there. A device that is not a hub
// only wants forwarding off; where the setting cannot be written (read-only /proc/sys in an
// unprivileged container) that is logged and the tunnel still comes up.
func applyForwarding(d forwardingSetter, hub bool, logf func(format string, args ...any)) error {
	err := d.SetForwarding(hub)
	if err == nil {
		return nil
	}
	if hub {
		return fmt.Errorf("a hub needs IP forwarding: %w", err)
	}
	logf("could not turn IP forwarding off on the tunnel interface (%v); it stays at the system default", err)
	return nil
}
