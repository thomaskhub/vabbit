// Package config reads vabbit.toml, the description of the networks to
// deploy on bunny.net.
package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

type File struct {
	// APIKeyEnv names the environment variable holding the Bunny account API
	// key. The key itself never goes in the file.
	APIKeyEnv string `toml:"api_key_env"`
	// Script is the built edge script (edge/dist/edge-script.js). Empty means
	// the copy built into vabbit-deploy.
	Script   string    `toml:"script"`
	Networks []Network `toml:"network"`
}

type Network struct {
	Name               string   `toml:"name"`
	CIDR               string   `toml:"cidr"`
	ScriptName         string   `toml:"script_name"`
	StorageZone        string   `toml:"storage_zone"`
	StorageRegion      string   `toml:"storage_region"`
	ReplicationRegions []string `toml:"replication_regions"`
	// AdminTokenSHA256 pins the admin token hash. Empty: generate a token on
	// the first deploy and keep whatever is set after that.
	AdminTokenSHA256 string `toml:"admin_token_sha256"`
}

var (
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	zoneRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	hashRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envRE    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	regions  = map[string]bool{"DE": true, "NY": true, "LA": true, "SG": true}
	replicas = map[string]bool{"DE": true, "NY": true, "LA": true, "SG": true, "SYD": true}
)

// Load reads and validates a config file, filling in defaults.
func Load(path string) (File, error) {
	var f File
	md, err := toml.DecodeFile(path, &f)
	if err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		return File{}, fmt.Errorf("%s: unknown setting %q", path, un[0].String())
	}
	if err := f.normalize(); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

func (f *File) normalize() error {
	if f.APIKeyEnv == "" {
		f.APIKeyEnv = "BUNNY_API_KEY"
	}
	if !envRE.MatchString(f.APIKeyEnv) {
		return fmt.Errorf("api_key_env must be an environment variable name, not the key itself")
	}
	if len(f.Networks) == 0 {
		return fmt.Errorf("no [[network]] defined")
	}
	seen := map[string]bool{}
	for i := range f.Networks {
		n := &f.Networks[i]
		if !nameRE.MatchString(n.Name) {
			return fmt.Errorf("network name %q: use lowercase letters, digits and dashes", n.Name)
		}
		if seen[n.Name] {
			return fmt.Errorf("network %q defined twice", n.Name)
		}
		seen[n.Name] = true
		if n.CIDR == "" {
			n.CIDR = "100.92.0.0/16"
		}
		p, err := netip.ParsePrefix(n.CIDR)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 8 || p.Bits() > 28 {
			return fmt.Errorf("network %q: cidr %q must be an IPv4 network between /8 and /28", n.Name, n.CIDR)
		}
		if n.ScriptName == "" {
			n.ScriptName = "vabbit-" + n.Name
		}
		if n.StorageZone == "" {
			n.StorageZone = "vabbit-" + n.Name + "-state"
		}
		if !nameRE.MatchString(n.ScriptName) || !zoneRE.MatchString(n.StorageZone) {
			return fmt.Errorf("network %q: script_name and storage_zone use lowercase letters, digits and dashes", n.Name)
		}
		n.StorageRegion = strings.ToUpper(n.StorageRegion)
		if n.StorageRegion == "" {
			n.StorageRegion = "DE"
		}
		if !regions[n.StorageRegion] {
			return fmt.Errorf("network %q: storage_region %q is not one of DE, NY, LA, SG", n.Name, n.StorageRegion)
		}
		for j, r := range n.ReplicationRegions {
			n.ReplicationRegions[j] = strings.ToUpper(r)
			if !replicas[n.ReplicationRegions[j]] {
				return fmt.Errorf("network %q: unknown replication region %q", n.Name, r)
			}
		}
		n.AdminTokenSHA256 = strings.ToLower(n.AdminTokenSHA256)
		if n.AdminTokenSHA256 != "" && !hashRE.MatchString(n.AdminTokenSHA256) {
			return fmt.Errorf("network %q: admin_token_sha256 must be 64 hex characters (the hash, never the token)", n.Name)
		}
	}
	return nil
}

func (f File) Network(name string) (Network, bool) {
	for _, n := range f.Networks {
		if n.Name == name {
			return n, true
		}
	}
	return Network{}, false
}

// Example is written by `vabbit-deploy init`.
const Example = `# Vabbit networks on bunny.net. Deploy with:
#   export BUNNY_API_KEY=...        # Account settings > API key
#   vabbit-deploy apply
#
# Each [[network]] becomes one edge script and one private storage zone.

# Environment variable holding the Bunny API key. Never put the key in this file.
api_key_env = "BUNNY_API_KEY"

[[network]]
name = "home"                    # shown by "vabbit login"
cidr = "100.92.0.0/16"           # VPN addresses; cannot change once devices exist
storage_region = "DE"            # DE, NY, LA or SG
# replication_regions = ["NY"]
# script_name = "vabbit-home"          # default vabbit-<name>
# storage_zone = "vabbit-home-state"   # default vabbit-<name>-state
# admin_token_sha256 = ""        # empty: a token is generated on the first apply

# [[network]]
# name = "work"
# cidr = "100.93.0.0/16"
`
