package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func TestSetupKeyReplace(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/setup-keys":
			got = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`{"key":"vbk_x","id":"abc","reusable":false,"maxUses":1,"uses":0,"expiresAt":null,"replace":true}`))
		case "GET /api/v1/setup-keys":
			_, _ = w.Write([]byte(`{"setupKeys":[{"id":"a","replace":true},{"id":"b"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "vba_test")
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateSetupKey(context.Background(), SetupKeyOptions{Replace: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if got["replace"] != true || !k.Replace {
		t.Errorf("replace not sent or not read back: sent %v, read %v", got["replace"], k.Replace)
	}
	if _, err := c.CreateSetupKey(context.Background(), SetupKeyOptions{TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, sent := got["replace"]; sent {
		t.Errorf("a key without --replace must not send the field, got %v", got)
	}
	keys, err := c.ListSetupKeys(context.Background())
	if err != nil || len(keys) != 2 || !keys[0].Replace || keys[1].Replace {
		t.Errorf("list: %v %+v", err, keys)
	}
}
