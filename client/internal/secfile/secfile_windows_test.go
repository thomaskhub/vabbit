//go:build windows

package secfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectAndCheck(t *testing.T) {
	for _, s := range []Scope{Machine, User} {
		dir := filepath.Join(t.TempDir(), "vabbit")
		if err := MkdirAll(dir, s); err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp(dir, "x")
		if err != nil {
			t.Fatal(err)
		}
		if err := Protect(f, s); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if err := Check(f.Name()); err != nil {
			t.Fatalf("scope %d: protected file refused: %v", s, err)
		}
		// Give Everyone read access: Check must refuse it.
		sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FR;;;WD)")
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, _ := sd.DACL()
		if err := windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
		if err := Check(f.Name()); err == nil || !strings.Contains(err.Error(), "S-1-1-0") {
			t.Fatalf("file readable by Everyone accepted: %v", err)
		}
	}
}
