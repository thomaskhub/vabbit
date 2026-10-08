package agent

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeForwarding struct {
	err     error
	on      bool  // what Forwarding reports
	readErr error // what Forwarding fails with
	calls   []bool
}

func (f *fakeForwarding) Forwarding() (bool, error) { return f.on, f.readErr }

func (f *fakeForwarding) SetForwarding(on bool) error {
	f.calls = append(f.calls, on)
	return f.err
}

func TestApplyForwarding(t *testing.T) {
	roFS := errors.New("open /proc/sys/net/ipv4/conf/vb0/forwarding: read-only file system")
	tests := []struct {
		name     string
		hub      bool
		setErr   error
		on       bool
		readErr  error
		wantErr  bool
		wantLogs int
	}{
		{"hub, ok", true, nil, false, nil, false, 0},
		{"non-hub, ok", false, nil, false, nil, false, 0},
		{"non-hub, read-only /proc/sys, already off: warn and go on", false, roFS, false, nil, false, 1},
		{"non-hub, read-only /proc/sys, on: fatal", false, roFS, true, nil, true, 0},
		{"non-hub, read-only /proc/sys, unreadable: fatal", false, roFS, false, errors.New("no such file"), true, 0},
		{"hub, read-only /proc/sys: fatal", true, roFS, false, nil, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeForwarding{err: tc.setErr, on: tc.on, readErr: tc.readErr}
			var logs []string
			logf := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
			err := applyForwarding(f, tc.hub, logf)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, tc.setErr) {
				t.Errorf("error %v does not wrap the cause %v", err, tc.setErr)
			}
			if len(f.calls) != 1 || f.calls[0] != tc.hub {
				t.Errorf("SetForwarding calls = %v, want one call with %v", f.calls, tc.hub)
			}
			if len(logs) != tc.wantLogs {
				t.Fatalf("logs = %q, want %d line(s)", logs, tc.wantLogs)
			}
			if tc.wantLogs == 1 && !strings.Contains(logs[0], "read-only file system") {
				t.Errorf("the warning does not name the cause: %q", logs[0])
			}
		})
	}
}
