//go:build !unix

package hosts

import "os"

// No file locking or owners here; the agent only manages /etc/hosts on Linux today.
func flock(*os.File) error                  { return nil }
func sameOwner(*os.File, os.FileInfo) error { return nil }
