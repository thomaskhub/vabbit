// Package hosts keeps a managed block in /etc/hosts so that devices can reach each other by name.
// Only the lines between "# BEGIN vabbit <iface>" and "# END vabbit <iface>" belong to Vabbit.
package hosts

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
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

// Apply writes the block of iface into the file at path, in place, and reports whether the file
// changed. It does not create a temporary file and rename it: /etc/hosts is a bind mount in
// containers, and a sandboxed service may be allowed to write that one file but not its directory.
// The new content is written from the start of the file before it is cut to its length, so readers
// never see an empty file.
func Apply(path, iface string, entries []Entry) (bool, error) {
	cur, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	next, err := Replace(string(cur), iface, Block(iface, entries))
	if err != nil {
		return false, err
	}
	if next == string(cur) {
		return false, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteAt([]byte(next), 0); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Truncate(int64(len(next))); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
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
