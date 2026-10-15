package bunny

import "testing"

func TestHostnameStripsScheme(t *testing.T) {
	for in, want := range map[string]string{
		"https://vabbit-home.bunny.run": "vabbit-home.bunny.run",
		"vabbit-home.b-cdn.net":         "vabbit-home.b-cdn.net",
		"http://x.example.com/":         "x.example.com",
	} {
		s := Script{DefaultHostname: in}
		if got := s.Hostname(); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
