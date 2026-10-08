//go:build windows

package hosts

import (
	"os"

	"golang.org/x/sys/windows"
)

// flock takes an exclusive lock on a byte range far past the end of the file. Windows locks are
// mandatory, so locking the content itself would also block our own in-place write through a
// second handle; a range nobody writes serializes the writers without that. The lock goes away
// when f is closed.
func flock(f *os.File) error {
	var ol windows.Overlapped
	ol.OffsetHigh = 0x40000000
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// sameOwner is not needed: the file is always rewritten in place on Windows.
func sameOwner(*os.File, os.FileInfo) error { return nil }
