package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"vabbit-deploy/internal/bunny"
	"vabbit-deploy/internal/config"
)

// fakeBunny is an in-memory stand-in for the parts of api.bunny.net we use.
type fakeBunny struct {
	mu       sync.Mutex
	nextID   int64
	zones    map[int64]map[string]any
	scripts  map[int64]*fakeScript
	writes   int
	publishN int
}

type fakeScript struct {
	name    string
	draft   string
	live    string
	vars    map[string]string
	secrets map[string]string
}

func newFake(t *testing.T) (*fakeBunny, *bunny.Client) {
	f := &fakeBunny{nextID: 100, zones: map[int64]map[string]any{}, scripts: map[int64]*fakeScript{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := bunny.New(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *fakeBunny) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("AccessKey") != "test-key" {
		w.WriteHeader(401)
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	if r.Method != "GET" {
		f.writes++
	}
	out := func(v any) { json.NewEncoder(w).Encode(v) }
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/storagezone" && r.Method == "GET":
		list := []map[string]any{}
		for _, z := range f.zones {
			list = append(list, z)
		}
		out(list)
	case r.URL.Path == "/storagezone" && r.Method == "POST":
		f.nextID++
		z := map[string]any{"Id": f.nextID, "Name": in["Name"], "Region": in["Region"], "Password": "zone-pw-" + in["Name"].(string), "StorageHostname": "storage.bunnycdn.com"}
		f.zones[f.nextID] = z
		w.WriteHeader(201)
		out(z)
	case len(parts) == 2 && parts[0] == "storagezone" && r.Method == "DELETE":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		delete(f.zones, id)
		w.WriteHeader(204)
	case r.URL.Path == "/compute/script" && r.Method == "GET":
		items := []map[string]any{}
		for id, s := range f.scripts {
			items = append(items, f.scriptJSON(id, s))
		}
		out(map[string]any{"Items": items, "HasMoreItems": false})
	case r.URL.Path == "/compute/script" && r.Method == "POST":
		f.nextID++
		f.scripts[f.nextID] = &fakeScript{name: in["Name"].(string), draft: in["Code"].(string), vars: map[string]string{}, secrets: map[string]string{}}
		w.WriteHeader(201)
		out(f.scriptJSON(f.nextID, f.scripts[f.nextID]))
	case len(parts) >= 3 && parts[0] == "compute":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		s := f.scripts[id]
		if s == nil {
			w.WriteHeader(404)
			return
		}
		switch sub := strings.Join(parts[3:], "/"); {
		case sub == "" && r.Method == "GET":
			out(f.scriptJSON(id, s))
		case sub == "" && r.Method == "DELETE":
			delete(f.scripts, id)
			w.WriteHeader(204)
		case sub == "releases/active":
			if s.live == "" {
				w.WriteHeader(404)
				return
			}
			out(map[string]any{"Code": s.live})
		case sub == "code":
			s.draft = in["Code"].(string)
		case sub == "variables" && r.Method == "PUT":
			s.vars[in["Name"].(string)] = in["DefaultValue"].(string)
		case sub == "secrets" && r.Method == "GET":
			list := []map[string]any{}
			for n := range s.secrets {
				list = append(list, map[string]any{"Name": n})
			}
			out(map[string]any{"Secrets": list})
		case sub == "secrets" && r.Method == "PUT":
			s.secrets[in["Name"].(string)] = in["Secret"].(string)
		case sub == "publish":
			s.live = s.draft
			f.publishN++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeBunny) scriptJSON(id int64, s *fakeScript) map[string]any {
	vars := []map[string]any{}
	for k, v := range s.vars {
		vars = append(vars, map[string]any{"Name": k, "DefaultValue": v})
	}
	return map[string]any{"Id": id, "Name": s.name, "ScriptType": 1, "EdgeScriptVariables": vars,
		"LinkedPullZones": []map[string]any{{"Id": id + 1000, "DefaultHostname": s.name + ".b-cdn.net"}}}
}

func (f *fakeBunny) script(name string) *fakeScript {
	for _, s := range f.scripts {
		if s.name == name {
			return s
		}
	}
	return nil
}

func network(t *testing.T) config.Network {
	path := t.TempDir() + "/e.toml"
	writeFile(t, path, "[[network]]\nname = \"home\"\n")
	f, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return f.Networks[0]
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestApplyCreatesEverythingThenIsIdempotent(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	n := network(t)
	var out bytes.Buffer
	res, err := Apply(ctx, c, n, "code-v1", Options{Out: &out})
	if err != nil {
		t.Fatal(err, out.String())
	}
	if res.URL != "https://vabbit-home.b-cdn.net" || !strings.HasPrefix(res.AdminToken, "vba_") {
		t.Fatalf("result %+v", res)
	}
	s := f.script("vabbit-home")
	if s.live != "code-v1" || f.publishN != 1 {
		t.Fatalf("not published: live=%q publishes=%d", s.live, f.publishN)
	}
	if s.secrets["ADMIN_TOKEN_SHA256"] != sha(res.AdminToken) || s.secrets["STORAGE_ACCESS_KEY"] != "zone-pw-vabbit-home-state" {
		t.Fatalf("secrets %v", s.secrets)
	}
	for k, v := range map[string]string{"NETWORK_NAME": "home", "NETWORK_CIDR": "100.92.0.0/16", "STORAGE_ZONE": "vabbit-home-state", "STORAGE_HOST": "storage.bunnycdn.com"} {
		if s.vars[k] != v {
			t.Fatalf("var %s=%q want %q", k, s.vars[k], v)
		}
	}
	if strings.Contains(out.String(), res.AdminToken) || strings.Contains(out.String(), "zone-pw") {
		t.Fatalf("secret printed in step log:\n%s", out.String())
	}

	writes := f.writes
	out.Reset()
	res, err = Apply(ctx, c, n, "code-v1", Options{Out: &out})
	if err != nil || res.Changed || res.AdminToken != "" || f.writes != writes {
		t.Fatalf("second apply changed things: %+v %v writes %d->%d\n%s", res, err, writes, f.writes, out.String())
	}

	// New code is uploaded and published; the admin token stays.
	hash := s.secrets["ADMIN_TOKEN_SHA256"]
	if res, err = Apply(ctx, c, n, "code-v2", Options{Out: &out}); err != nil || !res.Changed {
		t.Fatal(err)
	}
	if s.live != "code-v2" || s.secrets["ADMIN_TOKEN_SHA256"] != hash {
		t.Fatalf("code update: live=%q", s.live)
	}
}

func TestPlanWritesNothing(t *testing.T) {
	f, c := newFake(t)
	var out bytes.Buffer
	res, err := Apply(context.Background(), c, network(t), "code", Options{DryRun: true, Out: &out})
	if err != nil || f.writes != 0 || !res.Changed {
		t.Fatalf("plan: %v writes=%d", err, f.writes)
	}
	if !strings.Contains(out.String(), "would create edge script") {
		t.Fatal(out.String())
	}
}

func TestCIDRChangeRefused(t *testing.T) {
	ctx := context.Background()
	_, c := newFake(t)
	n := network(t)
	var out bytes.Buffer
	if _, err := Apply(ctx, c, n, "code", Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	n.CIDR = "100.93.0.0/16"
	if _, err := Apply(ctx, c, n, "code", Options{Out: &out}); err == nil || !strings.Contains(err.Error(), "cut off every device") {
		t.Fatalf("want refusal, got %v", err)
	}
	if _, err := Apply(ctx, c, n, "code", Options{Out: &out, AllowCIDRChange: true}); err != nil {
		t.Fatal(err)
	}
}

func TestPublicStorageZoneRefused(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	n := network(t)
	f.zones[1] = map[string]any{"Id": 1, "Name": n.StorageZone, "Region": "DE", "Password": "pw", "PullZones": []map[string]any{{"Id": 9, "Name": "oops"}}}
	if _, err := Apply(ctx, c, n, "code", Options{Out: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestPinnedHashAndRotation(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	n := network(t)
	n.AdminTokenSHA256 = sha("vba_one")
	res, err := Apply(ctx, c, n, "code", Options{Out: &bytes.Buffer{}})
	if err != nil || res.AdminToken != "" {
		t.Fatalf("%v %+v", err, res)
	}
	s := f.script(n.ScriptName)
	if s.secrets["ADMIN_TOKEN_SHA256"] != sha("vba_one") {
		t.Fatal("pinned hash not set")
	}
	// Changing the pinned hash in the config rotates the token.
	n.AdminTokenSHA256 = sha("vba_two")
	if res, err = Apply(ctx, c, n, "code", Options{Out: &bytes.Buffer{}}); err != nil || !res.Changed {
		t.Fatal(err)
	}
	if s.secrets["ADMIN_TOKEN_SHA256"] != sha("vba_two") {
		t.Fatal("pinned hash not updated")
	}
	if _, _, err := RotateAdmin(ctx, c, n); err == nil {
		t.Fatal("rotate-admin must refuse a pinned hash")
	}

	n.AdminTokenSHA256 = ""
	tok, url, err := RotateAdmin(ctx, c, n)
	if err != nil || url != "https://vabbit-home.b-cdn.net" || s.secrets["ADMIN_TOKEN_SHA256"] != sha(tok) || s.live != "code" {
		t.Fatalf("rotate: %v", err)
	}
	// A later apply keeps the rotated token.
	if res, err = Apply(ctx, c, n, "code", Options{Out: &bytes.Buffer{}}); err != nil || res.Changed || s.secrets["ADMIN_TOKEN_SHA256"] != sha(tok) {
		t.Fatalf("apply after rotate: %v %+v", err, res)
	}
}

func TestDestroy(t *testing.T) {
	ctx := context.Background()
	f, c := newFake(t)
	n := network(t)
	if _, err := Apply(ctx, c, n, "code", Options{Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	if err := Destroy(ctx, c, n, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if f.script(n.ScriptName) != nil || len(f.zones) != 0 {
		t.Fatal("not deleted")
	}
	// Destroying again is a no-op.
	if err := Destroy(ctx, c, n, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
