package main

import (
	"testing"
	"time"
)

func TestParseLifetime(t *testing.T) {
	ok := map[string]time.Duration{
		"never": 0, "0": 0, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour,
		"1d12h": 36 * time.Hour, "30m": 30 * time.Minute,
	}
	for in, want := range ok {
		if got, err := parseLifetime(in); err != nil || got != want {
			t.Errorf("%s: got %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "abc", "-1h", "xd", "10s", "d"} {
		if _, err := parseLifetime(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
