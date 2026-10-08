//go:build !linux

package wg

import (
	"errors"
	"regexp"
)

var errUnsupported = errors.New("this platform is not supported yet (Linux only for now)")

var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func ValidIface(name string) bool { return ifaceRE.MatchString(name) }

func Apply(string, Interface, bool) error { return errUnsupported }
func Down(string) error                   { return errUnsupported }
func Show(string) (string, error)         { return "", errUnsupported }
