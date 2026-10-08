//go:build !windows && !darwin

package main

import (
	"context"
	"errors"
)

// runAsService runs a Windows service; elsewhere systemd runs `vabbit up` directly.
func runAsService(func(context.Context) error) bool { return false }

func cmdService([]string) error {
	return errors.New("vabbit service is for macOS and Windows; on Linux use the systemd unit: systemctl enable --now vabbit@vb0")
}

func afterLeave(string) {}
