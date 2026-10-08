//go:build darwin

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"vabbit/internal/state"
	"vabbit/internal/wg"
)

// runAsService runs a Windows service; launchd runs `vabbit up` directly.
func runAsService(func(context.Context) error) bool { return false }

const serviceUsage = "usage: vabbit service install|uninstall [--iface vb0]"

// cmdService installs or removes the launchd service that runs `vabbit up --iface IFACE`.
func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New(serviceUsage)
	}
	fs := flag.NewFlagSet("service "+args[0], flag.ExitOnError)
	iface := fs.String("iface", "vb0", "interface name")
	fs.Parse(args[1:])
	if !wg.ValidIface(*iface) {
		return fmt.Errorf("invalid interface name %q", *iface)
	}
	if !privileged() {
		return errors.New("must run as root (sudo)")
	}
	switch args[0] {
	case "install":
		return installService(*iface)
	case "uninstall":
		return removeService(*iface)
	}
	return errors.New(serviceUsage)
}

func logPath(iface string) string { return "/var/log/vabbit-" + iface + ".log" }

// plist is the launchd job: start at boot, restart when it exits, log to /var/log.
func plist(exe, iface string) string {
	x := html.EscapeString
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + x(wg.ServiceLabel(iface)) + `</string>
	<key>ProgramArguments</key>
	<array><string>` + x(exe) + `</string><string>up</string><string>--iface</string><string>` + x(iface) + `</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>10</integer>
	<key>StandardOutPath</key><string>` + x(logPath(iface)) + `</string>
	<key>StandardErrorPath</key><string>` + x(logPath(iface)) + `</string>
</dict>
</plist>
`
}

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installService(iface string) error {
	if err := state.Load(state.DevicePath(state.DefaultDir, iface), &state.Device{}); err != nil {
		return fmt.Errorf("enroll first with `vabbit up --dry-run --server URL --setup-key KEY`: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	path := wg.ServicePlist(iface)
	_ = launchctl("bootout", "system/"+wg.ServiceLabel(iface)) // a reinstall replaces the running job
	if err := os.WriteFile(path, []byte(plist(exe, iface)), 0o644); err != nil {
		return err
	}
	if err := launchctl("bootstrap", "system", path); err != nil {
		return err
	}
	fmt.Printf("Started %s. Check it with: sudo vabbit status --iface %s (log: %s)\n", wg.ServiceLabel(iface), iface, logPath(iface))
	return nil
}

func removeService(iface string) error {
	path := wg.ServicePlist(iface)
	if _, err := os.Stat(path); err != nil {
		return nil // not installed
	}
	_ = launchctl("bootout", "system/"+wg.ServiceLabel(iface))
	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Printf("Removed service %s.\n", wg.ServiceLabel(iface))
	return nil
}

// afterLeave removes the service of a device that left the network, so it
// doesn't start again without state.
func afterLeave(iface string) { _ = removeService(iface) }
