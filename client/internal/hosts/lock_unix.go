//go:build unix

package hosts

import (
	"os"
	"syscall"
)

// flock takes an exclusive lock on f; it is released when f is closed.
func flock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

// sameOwner gives tmp the owner and group of the file described by fi, when they differ from ours.
func sameOwner(tmp *os.File, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) == os.Geteuid() && int(st.Gid) == os.Getegid()) {
		return nil
	}
	return tmp.Chown(int(st.Uid), int(st.Gid))
}
