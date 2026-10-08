// Package secfile keeps files that hold secrets (device keys and tokens, the
// admin login) private: mode 0600 in a 0700 directory on Unix, an ACL that
// only allows SYSTEM, Administrators (and, for a user's own file, that user)
// on Windows.
package secfile

// Scope says who besides the system and administrators may use a file.
type Scope int

const (
	// Machine files (device state) are for root / SYSTEM and Administrators only.
	Machine Scope = iota
	// User files (the admin login) also belong to the user who runs vabbit.
	User
)
