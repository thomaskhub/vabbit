package api

import "testing"

func TestValidateServer(t *testing.T) {
	ok := map[string]string{
		"https://net.b-cdn.net":  "https://net.b-cdn.net",
		"https://net.b-cdn.net/": "https://net.b-cdn.net",
		"http://127.0.0.1:8787":  "http://127.0.0.1:8787",
		"http://localhost:8787":  "http://localhost:8787",
	}
	for in, want := range ok {
		if got, err := ValidateServer(in); err != nil || got != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://net.b-cdn.net", "ftp://x", "https://u:p@x", "https://x/path", "https://x?a=1", "x"} {
		if _, err := ValidateServer(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
