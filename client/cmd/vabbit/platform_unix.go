//go:build !windows

package main

import "os"

const needPrivilege = "must run as root to configure WireGuard (or use --dry-run)"

func privileged() bool { return os.Geteuid() == 0 }
