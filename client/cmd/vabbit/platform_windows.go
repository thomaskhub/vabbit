//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"vabbit/internal/secfile"
	"vabbit/internal/state"
	"vabbit/internal/wg"
)

const needPrivilege = "must run as Administrator to configure WireGuard (or use --dry-run)"

func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

// runAsService runs fn as a Windows service when the process was started by
// the service manager, and reports whether it did. Stop and shutdown cancel
// fn's context. The log goes to %ProgramData%\vabbit\vabbit.log.
func runAsService(fn func(context.Context) error) bool {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return false
	}
	if err := secfile.MkdirAll(state.DefaultDir, secfile.Machine); err == nil {
		path := filepath.Join(state.DefaultDir, "vabbit.log")
		if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<20 {
			_ = os.Rename(path, path+".1")
		}
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(f)
			os.Stderr = f
			os.Stdout = f
		}
	}
	err := svc.Run("vabbit", handler(fn))
	if err != nil {
		log.Printf("service: %v", err)
	}
	return true
}

type handler func(context.Context) error

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Printf("error: %v", err)
				return false, 1 // non-zero: the service manager's recovery restarts it
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		}
	}
}

const serviceUsage = "usage: vabbit service install|uninstall [--iface vb0]"

// cmdService installs or removes the Windows service that runs `vabbit up --iface IFACE`.
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
		return errors.New("must run as Administrator")
	}
	switch args[0] {
	case "install":
		return installService(*iface)
	case "uninstall":
		return removeService(*iface)
	}
	return errors.New(serviceUsage)
}

func installService(iface string) error {
	if err := state.Load(state.DevicePath(state.DefaultDir, iface), &state.Device{}); err != nil {
		return fmt.Errorf("enroll first with `vabbit up --dry-run --server URL --setup-key KEY`: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	name := wg.ServiceName(iface)
	s, err := m.OpenService(name)
	if err != nil {
		s, err = m.CreateService(name, exe, mgr.Config{
			DisplayName: "Vabbit (" + iface + ")",
			Description: "Vabbit WireGuard agent for interface " + iface,
			StartType:   mgr.StartAutomatic,
		}, "up", "--iface", iface)
		if err != nil {
			return err
		}
		fmt.Printf("Installed service %s.\n", name)
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	fmt.Printf("Started %s. Check it with: vabbit status --iface %s (log: %s)\n", name, iface, filepath.Join(state.DefaultDir, "vabbit.log"))
	return nil
}

func removeService(iface string) error {
	_ = wg.Down(iface)
	wg.RemoveInbound(iface)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(wg.ServiceName(iface))
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("Removed service %s.\n", wg.ServiceName(iface))
	return nil
}

// afterLeave removes the service of a device that left the network, so it
// doesn't start again without state.
func afterLeave(iface string) { _ = removeService(iface) }
