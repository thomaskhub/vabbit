package config

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, body string) (File, error) {
	t.Helper()
	p := t.TempDir() + "/c.toml"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestExampleLoads(t *testing.T) {
	f, err := load(t, Example)
	if err != nil {
		t.Fatal(err)
	}
	n := f.Networks[0]
	if f.APIKeyEnv != "BUNNY_API_KEY" || n.Name != "home" || n.ScriptName != "vabbit-home" || n.StorageZone != "vabbit-home-state" || n.StorageRegion != "DE" {
		t.Fatalf("%+v", f)
	}
}

func TestRejects(t *testing.T) {
	for body, want := range map[string]string{
		`api_key_env = "abc123-secret"` + "\n[[network]]\nname=\"a\"": "environment variable name",
		"[[network]]\nname=\"a\"\nadmin_token = \"vba_x\"":            "unknown setting",
		"[[network]]\nname=\"a\"\ncidr=\"0.0.0.0/0\"":                 "between /8 and /28",
		"[[network]]\nname=\"a\"\ncidr=\"100.92.1.0/16\"":             "between /8 and /28",
		"[[network]]\nname=\"Bad Name\"":                              "lowercase",
		"[[network]]\nname=\"a\"\n[[network]]\nname=\"a\"":            "twice",
		"[[network]]\nname=\"a\"\nstorage_region=\"XX\"":              "storage_region",
		"": "no [[network]]",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
}
