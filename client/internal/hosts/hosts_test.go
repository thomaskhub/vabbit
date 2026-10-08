package hosts

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func entries() []Entry {
	return []Entry{
		{Addr: netip.MustParseAddr("100.92.0.9"), Name: "web.vabbit"},
		{Addr: netip.MustParseAddr("100.92.0.5"), Name: "db.vabbit"},
	}
}

const want = "# BEGIN vabbit vb0\n100.92.0.5 db.vabbit\n100.92.0.9 web.vabbit\n# END vabbit vb0\n"

func TestBlock(t *testing.T) {
	if got := Block("vb0", entries()); got != want {
		t.Errorf("Block = %q, want %q (sorted by name, deterministic)", got, want)
	}
	if got := Block("vb0", nil); got != "" {
		t.Errorf("no entries must give no block, got %q", got)
	}
}

func TestReplace(t *testing.T) {
	user := "127.0.0.1 localhost\n::1 localhost\n10.0.0.7 printer\n"
	for _, tc := range []struct {
		name, in, block, want string
		wantErr               bool
	}{
		{"append to a file without our block", user, want, user + want, false},
		{"append when the last line has no newline", "127.0.0.1 localhost", want, "127.0.0.1 localhost\n" + want, false},
		{"empty file", "", want, want, false},
		{"replace in place, lines around it stay", "a 1\n" + "# BEGIN vabbit vb0\nold stuff\n# END vabbit vb0\n" + "b 2\n", want, "a 1\n" + want + "b 2\n", false},
		{"remove the block", user + want + "tail 3\n", "", user + "tail 3\n", false},
		{"remove when there is none", user, "", user, false},
		{"another interface's block is not ours", user + "# BEGIN vabbit vb1\n1.1.1.1 x.vabbit\n# END vabbit vb1\n", want, user + "# BEGIN vabbit vb1\n1.1.1.1 x.vabbit\n# END vabbit vb1\n" + want, false},
		{"unterminated block is an error, nothing is dropped", user + "# BEGIN vabbit vb0\n1.1.1.1 x.vabbit\n" + "more user lines\n", want, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Replace(tc.in, "vb0", tc.block)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
			if !tc.wantErr {
				again, err := Replace(got, "vb0", tc.block)
				if err != nil || again != got {
					t.Errorf("not idempotent: %q then %q (%v)", got, again, err)
				}
			}
		})
	}
}

func TestApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Apply(path, "vb0", entries())
	if err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "127.0.0.1 localhost\n"+want {
		t.Errorf("file = %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode changed to %o", fi.Mode().Perm())
	}
	if changed, err = Apply(path, "vb0", entries()); err != nil || changed {
		t.Errorf("same entries must not write: changed=%v err=%v", changed, err)
	}
	// a shorter block must not leave bytes of the longer one behind
	if _, err = Apply(path, "vb0", entries()[:1]); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "db.vabbit") || !strings.Contains(string(b), "web.vabbit") || !strings.HasSuffix(string(b), "# END vabbit vb0\n") {
		t.Errorf("file after shrinking = %q", b)
	}
	if changed, err = Apply(path, "vb0", nil); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	b, _ = os.ReadFile(path)
	if string(b) != "127.0.0.1 localhost\n" {
		t.Errorf("after removing the block: %q", b)
	}
}

func TestApplyInPlaceWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"+want), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	rename = func(string, string) error { return &os.LinkError{Op: "rename", Err: syscall.EBUSY} } // bind mount
	defer func() { rename = os.Rename }()
	if _, err := Apply(path, "vb0", entries()[:1]); err != nil {
		t.Fatalf("a bind-mounted file must be written in place: %v", err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "127.0.0.1 localhost\n# BEGIN vabbit vb0\n100.92.0.9 web.vabbit\n# END vabbit vb0\n" {
		t.Errorf("file = %q (shorter content must leave nothing behind)", b)
	}
	if after, _ := os.Stat(path); !os.SameFile(before, after) {
		t.Error("the file was replaced instead of written in place")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".hosts.vabbit-*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestApplyReplacesTheFileAndKeepsItsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if _, err := Apply(path, "vb0", entries()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if os.SameFile(before, after) {
		t.Error("expected a new file renamed over the old one")
	}
	if after.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", after.Mode().Perm())
	}
	// nothing to change: the file is not rewritten
	if changed, err := Apply(path, "vb0", entries()); err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if again, _ := os.Stat(path); !os.SameFile(after, again) || !again.ModTime().Equal(after.ModTime()) {
		t.Error("an unchanged block must not rewrite the file")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".hosts.vabbit-*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestApplyPutsBackARemovedBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if _, err := Apply(path, "vb0", entries()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil { // e.g. cloud-init
		t.Fatal(err)
	}
	if changed, err := Apply(path, "vb0", entries()); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "127.0.0.1 localhost\n"+want {
		t.Errorf("file = %q", b)
	}
}

func TestApplyMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if changed, err := Apply(path, "vb0", nil); err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("removing from a missing file must not create it: %v", err)
	}
}

func TestApplyConcurrentInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Agents for many interfaces add their block at the same time: none may be lost.
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Apply(path, fmt.Sprintf("vb%d", i), entries()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	b, _ := os.ReadFile(path)
	for i := range 40 {
		if !strings.Contains(string(b), fmt.Sprintf("# BEGIN vabbit vb%d\n", i)) {
			t.Errorf("block of vb%d lost", i)
		}
	}
}
