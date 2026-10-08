// Package hosts keeps a managed block in /etc/hosts so that devices can reach each other by name.
// Only the lines between "# BEGIN vabbit <iface>" and "# END vabbit <iface>" belong to Vabbit.
package hosts

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// DefaultFile is the system hosts file.
const DefaultFile = "/etc/hosts"

// Entry is one line of the block: an address and a full host name.
type Entry struct {
	Addr netip.Addr
	Name string
}

func markers(iface string) (begin, end string) {
	return "# BEGIN vabbit " + iface, "# END vabbit " + iface
}

// Block renders the managed block for iface: entries sorted by name, duplicates (by name) dropped,
// so the same input always gives the same text. It is empty when there are no entries.
func Block(iface string, entries []Entry) string {
	if len(entries) == 0 {
		return ""
	}
	sorted := slices.Clone(entries)
	slices.SortStableFunc(sorted, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	begin, end := markers(iface)
	var sb strings.Builder
	sb.WriteString(begin + "\n")
	last := ""
	for _, e := range sorted {
		if e.Name == last {
			continue
		}
		last = e.Name
		fmt.Fprintf(&sb, "%s %s\n", e.Addr, e.Name)
	}
	sb.WriteString(end + "\n")
	return sb.String()
}

// Replace returns content with the block of iface replaced by block, or removed when block is empty.
// A block that is not there is appended (only when block is not empty). Lines outside the markers are
// kept as they are. A BEGIN marker without its END marker is an error: nothing is guessed or dropped.
func Replace(content, iface, block string) (string, error) {
	begin, end := markers(iface)
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	b := slices.Index(lines, begin)
	e := -1
	if b >= 0 {
		for i := b + 1; i < len(lines); i++ {
			if lines[i] == end {
				e = i
				break
			}
		}
		if e < 0 {
			return "", fmt.Errorf("the block %q has no end marker %q: fix the hosts file by hand", begin, end)
		}
	}
	var blockLines []string
	if block != "" {
		blockLines = strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	}
	var out []string
	switch {
	case b < 0 && block == "":
		return content, nil
	case b < 0:
		out = append(slices.Clone(lines), blockLines...)
	default:
		out = append(slices.Clone(lines[:b]), blockLines...)
		out = append(out, lines[e+1:]...)
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, "\n") + "\n", nil
}

// Apply writes the block of iface into the file at path and reports whether the file changed. It
// reads the file on every call and writes nothing when the content is already right, so it can run
// after every sync and puts back a block that someone else removed.
//
// Writers are serialized with flock on the file itself, so agents for different interfaces don't lose
// each other's block. The lock is taken on the file that is at path once the lock is held: a writer
// that renamed a new file over it in the meantime is waited for.
//
// The new content goes to a temporary file in the same directory that is synced and renamed over path,
// with the old mode and owner, so a crash leaves either the old or the new file. When that is not
// possible (a bind-mounted /etc/hosts in a container gives EBUSY, the service sandbox makes /etc
// read-only and only opens the file itself), the file is rewritten in place; see writeInPlace.
func Apply(path, iface string, entries []Entry) (bool, error) {
	block := Block(iface, entries)
	f, err := lockFile(path, block != "")
	if err != nil || f == nil {
		return false, err // f == nil: there is no file and nothing to write
	}
	defer f.Close() // also releases the lock
	cur, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	next, err := Replace(string(cur), iface, block)
	if err != nil {
		return false, err
	}
	if next == string(cur) {
		return false, nil
	}
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	err = replaceFile(path, fi, []byte(next))
	if err == nil {
		return true, nil
	}
	if !canNotReplace(err) {
		return false, err
	}
	return true, writeInPlace(path, []byte(next))
}

// lockFile opens path and takes an exclusive flock on it. A missing file is created when create is
// set; otherwise lockFile returns nil and no error.
func lockFile(path string, create bool) (*os.File, error) {
	for {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			if !create {
				return nil, nil
			}
			f, err = os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
		}
		if err != nil {
			return nil, err
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		// Another writer may have renamed a new file over path while we waited: lock that one instead.
		held, err1 := f.Stat()
		now, err2 := os.Stat(path)
		if err1 == nil && err2 == nil && os.SameFile(held, now) {
			return f, nil
		}
		f.Close()
		if err1 != nil {
			return nil, err1
		}
		if err2 != nil && !errors.Is(err2, os.ErrNotExist) {
			return nil, err2
		}
	}
}

// rename is os.Rename; tests replace it to take the in-place path.
var rename = os.Rename

// replaceFile writes data to a temporary file next to path with the mode and owner of fi, syncs it and
// renames it over path.
func replaceFile(path string, fi os.FileInfo, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".vabbit-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		return err
	}
	if st, isUnix := fi.Sys().(*syscall.Stat_t); isUnix && (int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid()) {
		if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rename(tmp.Name(), path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(filepath.Dir(path)); err == nil { // make the rename durable; best effort
		d.Sync()
		d.Close()
	}
	return nil
}

// canNotReplace reports whether err means that path cannot be replaced by a rename (bind mount,
// read-only or sandboxed directory, an owner we may not set) but may still be written in place.
func canNotReplace(err error) bool {
	for _, e := range []error{syscall.EBUSY, syscall.EXDEV, syscall.EROFS, syscall.EPERM, syscall.EACCES} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// writeInPlace rewrites the file at path in place: the new content is written from the start of the
// file, then the file is cut to its length and synced, so readers never see an empty file. It is not
// atomic: a crash between the write and the cut leaves the tail of a longer old content behind. Cutting
// first would instead show readers an empty file on every write, so this order is kept; the window is
// one syscall, and it only applies where a rename is impossible.
func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

// ValidHostName reports whether s is a valid lower-case host name: labels of letters, digits and
// hyphens, 1 to 63 characters each, not starting or ending with a hyphen, at most 253 in total.
func ValidHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < '0' || r > '9') && (r < 'a' || r > 'z') {
				return false
			}
		}
	}
	return true
}

// ValidDomain reports whether s can be the domain of the device names.
func ValidDomain(s string) bool { return ValidHostName(s) }
