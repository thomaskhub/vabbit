//go:build windows

package secfile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sddl builds a protected DACL (nothing inherited from the parent) that gives
// full access to SYSTEM, Administrators and, for User files, the current user.
func sddl(s Scope, inherit bool) (string, error) {
	flags := ""
	if inherit {
		flags = "OICI"
	}
	d := fmt.Sprintf("D:P(A;%[1]s;FA;;;SY)(A;%[1]s;FA;;;BA)", flags)
	if s == User {
		u, err := currentUser()
		if err != nil {
			return "", err
		}
		d += fmt.Sprintf("(A;%s;FA;;;%s)", flags, u.String())
	}
	return d, nil
}

func currentUser() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid, nil
}

func setDACL(path string, s Scope, inherit bool) error {
	text, err := sddl(s, inherit)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// MkdirAll creates dir and restricts it (and what is created in it later).
func MkdirAll(dir string, s Scope) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return setDACL(dir, s, true)
}

// Protect restricts f to SYSTEM, Administrators and, for User files, the current user.
func Protect(f *os.File, s Scope) error { return setDACL(f.Name(), s, false) }

// Check refuses a file whose ACL lets anyone else than SYSTEM, Administrators
// or the current user use it.
func Check(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("%s has no access list, so everyone can read it", path)
	}
	allowed := []*windows.SID{}
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return err
		}
		allowed = append(allowed, sid)
	}
	if u, err := currentUser(); err == nil {
		allowed = append(allowed, u)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		ok := false
		for _, a := range allowed {
			if sid.Equals(a) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%s can be read by %s; remove that access (only SYSTEM, Administrators and you may use it)", path, sid.String())
		}
	}
	return nil
}
