//go:build !linux && !windows

package wg

import (
	"errors"
	"net/netip"
	"regexp"

	"golang.zx2c4.com/wireguard/device"
)

// TODO(macos): configure addresses and routes natively.
var errUnsupported = errors.New("running a device is not supported on this platform yet (Linux and Windows only)")

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func ValidIface(name string) bool               { return ifaceRE.MatchString(name) }
func (d *Device) SetAddress(netip.Prefix) error { return errUnsupported }
func (d *Device) SetForwarding(bool) error      { return errUnsupported }
func (d *Device) Forwarding() (bool, error)     { return false, errUnsupported }
func serveUAPI(string, *device.Device) func()   { return nil }
func Show(string) (map[string]PeerStat, error)  { return nil, errUnsupported }

func Down(string) error { return errUnsupported }

func (d *Device) AllowInbound(netip.Prefix, int) error { return nil }
func RemoveInbound(string)                             {}
