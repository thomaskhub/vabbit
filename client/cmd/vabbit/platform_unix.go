//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
)

const needPrivilege = "must run as root to configure WireGuard (or use --dry-run)"

func privileged() bool { return os.Geteuid() == 0 }

// runAsService runs a Windows service; elsewhere systemd runs `vabbit up` directly.
func runAsService(func(context.Context) error) bool { return false }

func cmdService([]string) error {
	return errors.New("vabbit service is for Windows; on Linux use the systemd unit: systemctl enable --now vabbit@vb0")
}

func afterLeave(string) {}
