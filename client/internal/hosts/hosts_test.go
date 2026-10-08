package hosts

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

func TestApplyInPlaceInReadOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { // like /etc under a sandbox: only the file is writable
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	if _, err := Apply(path, "vb0", entries()); err != nil {
		t.Fatalf("a write that needs no new file in the directory must work: %v", err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "db.vabbit") {
		t.Errorf("not written: %q", b)
	}
}

func TestApplyRefusesAnUnterminatedBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	orig := "127.0.0.1 localhost\n# BEGIN vabbit vb0\n10.0.0.1 mine\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(path, "vb0", entries()); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Errorf("file was changed: %q", b)
	}
}

func TestValidDomain(t *testing.T) {
	for _, d := range []string{"vabbit", "vpn.example.com", "a-b.c1"} {
		if !ValidDomain(d) {
			t.Errorf("%q rejected", d)
		}
	}
	for _, d := range []string{"", ".", "a..b", "-a", "a-", "under_score", "has space", strings.Repeat("a", 64), "x.localhost?"} {
		if ValidDomain(d) {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestValidHostName(t *testing.T) {
	for _, n := range []string{"db", "ishanga-db-india-uat", "a.b", "web1"} {
		if !ValidHostName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", "Db", "under_score", "a?b", "-x", "x-", "a..b", ".a", "a b", strings.Repeat("a", 64)} {
		if ValidHostName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}
