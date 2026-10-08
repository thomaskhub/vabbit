package agent

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeForwarding struct {
	err   error
	calls []bool
}

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
		wantErr  bool
		wantLogs int
	}{
		{"hub, ok", true, nil, false, 0},
		{"non-hub, ok", false, nil, false, 0},
		{"non-hub, read-only /proc/sys: warn and go on", false, roFS, false, 1},
		{"hub, read-only /proc/sys: fatal", true, roFS, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeForwarding{err: tc.setErr}
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
