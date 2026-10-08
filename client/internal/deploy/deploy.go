// Package deploy turns a network from vabbit.toml into Bunny resources: a
// private storage zone and an edge script with its variables and secrets.
// Every step is idempotent, so apply can run as often as you like.
package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"vabbit/internal/deploy/bunny"
	"vabbit/internal/deploy/config"
)

// Variables that hold non-secret fingerprints of secrets, so apply can tell
// whether a secret is current without being able to read it back.
const (
	varAdminTokenID = "ADMIN_TOKEN_ID"
	varStorageKeyID = "STORAGE_KEY_ID"
)

type Options struct {
	DryRun          bool
	AllowCIDRChange bool
	Out             io.Writer
}

type Result struct {
	URL     string
	Changed bool
}

func (o Options) step(format string, a ...any) {
	prefix := "  "
	if o.DryRun {
		prefix = "  would "
	}
	fmt.Fprintf(o.Out, prefix+format+"\n", a...)
}

// Apply makes Bunny match the network definition. adminHash is the SHA-256 of
// the network's admin token; a plan may leave it empty.
func Apply(ctx context.Context, c *bunny.Client, n config.Network, code, adminHash string, o Options) (Result, error) {
	var res Result
	fmt.Fprintf(o.Out, "network %s\n", n.Name)

	// 1. Storage zone (private: never attach a pull zone to it).
	zone, err := c.FindStorageZone(ctx, n.StorageZone)
	switch {
	case errors.Is(err, bunny.ErrNotFound):
		o.step("create storage zone %s in %s", n.StorageZone, n.StorageRegion)
		res.Changed = true
		if !o.DryRun {
			if zone, err = c.CreateStorageZone(ctx, n.StorageZone, n.StorageRegion, n.ReplicationRegions); err != nil {
				return res, fmt.Errorf("create storage zone: %w", err)
			}
		}
	case err != nil:
		return res, fmt.Errorf("look up storage zone: %w", err)
	default:
		if len(zone.PullZones) > 0 {
			return res, fmt.Errorf("storage zone %s is attached to a pull zone, which would make the network state public; detach it first", n.StorageZone)
		}
		if zone.Region != "" && zone.Region != n.StorageRegion {
			fmt.Fprintf(o.Out, "  note: storage zone %s is in %s, not %s (a region can't be changed after creation)\n", n.StorageZone, zone.Region, n.StorageRegion)
		}
	}

	// 2. Edge script.
	script, err := c.FindScript(ctx, n.ScriptName)
	created := false
	switch {
	case errors.Is(err, bunny.ErrNotFound):
		o.step("create edge script %s with its own pull zone", n.ScriptName)
		res.Changed, created = true, true
		if o.DryRun {
			o.step("set variables, secrets and the admin token, and publish")
			return res, nil
		}
		if script, err = c.CreateScript(ctx, n.ScriptName, code); err != nil {
			return res, fmt.Errorf("create edge script: %w", err)
		}
		if script, err = c.GetScript(ctx, script.ID); err != nil {
			return res, err
		}
	case err != nil:
		return res, fmt.Errorf("look up edge script: %w", err)
	}
	if script.ScriptType != bunny.ScriptTypeStandalone {
		return res, fmt.Errorf("edge script %s exists but is not a standalone script", n.ScriptName)
	}

	// 3. Code.
	if !created {
		live, err := c.ActiveCode(ctx, script.ID)
		if err != nil {
			return res, fmt.Errorf("read live code: %w", err)
		}
		if live != code {
			o.step("upload new edge script code (%d bytes)", len(code))
			res.Changed = true
			if !o.DryRun {
				if err := c.SetCode(ctx, script.ID, code); err != nil {
					return res, fmt.Errorf("upload code: %w", err)
				}
			}
		}
	}

	// 4. Variables. Changing the CIDR strands every enrolled device, which pins it.
	if v, ok := script.Variable("NETWORK_CIDR"); ok && v.DefaultValue != "" && v.DefaultValue != n.CIDR && !o.AllowCIDRChange {
		return res, fmt.Errorf("network %s already uses %s; changing it to %s would cut off every device (re-run with --allow-cidr-change and re-enroll them)", n.Name, v.DefaultValue, n.CIDR)
	}
	vars := [][2]string{
		{"NETWORK_NAME", n.Name},
		{"NETWORK_CIDR", n.CIDR},
		{"STORAGE_ZONE", n.StorageZone},
	}
	if zone.StorageHostname != "" {
		vars = append(vars, [2]string{"STORAGE_HOST", zone.StorageHostname})
	}

	// 5. Secrets, tracked through their fingerprints.
	type secret struct{ name, value, idVar, id string }
	var secrets []secret
	if zone.Password != "" {
		secrets = append(secrets, secret{"STORAGE_ACCESS_KEY", zone.Password, varStorageKeyID, fingerprint(zone.Password)})
	} else if !o.DryRun {
		return res, errors.New("Bunny did not return the storage zone's access key; check the API key's permissions")
	}
	names, err := c.SecretNames(ctx, script.ID)
	if err != nil {
		return res, fmt.Errorf("list secrets: %w", err)
	}
	switch {
	case adminHash != "":
		secrets = append(secrets, secret{"ADMIN_TOKEN_SHA256", adminHash, varAdminTokenID, adminTokenID(adminHash)})
	case !o.DryRun:
		return res, errors.New("no admin token")
	case !names["ADMIN_TOKEN_SHA256"]:
		o.step("set the admin token")
		res.Changed = true
	}
	for _, s := range secrets {
		if v, ok := script.Variable(s.idVar); names[s.name] && ok && v.DefaultValue == s.id {
			continue
		}
		o.step("set secret %s", s.name)
		res.Changed = true
		if !o.DryRun {
			if err := c.UpsertSecret(ctx, script.ID, s.name, s.value); err != nil {
				return res, fmt.Errorf("set secret %s: %w", s.name, err)
			}
		}
		vars = append(vars, [2]string{s.idVar, s.id})
	}
	for _, kv := range vars {
		if v, ok := script.Variable(kv[0]); ok && v.DefaultValue == kv[1] {
			continue
		}
		o.step("set %s=%s", kv[0], kv[1])
		res.Changed = true
		if !o.DryRun {
			if err := c.UpsertVariable(ctx, script.ID, kv[0], kv[1]); err != nil {
				return res, fmt.Errorf("set variable %s: %w", kv[0], err)
			}
		}
	}

	// 6. Publish.
	if res.Changed {
		o.step("publish")
		if !o.DryRun {
			if err := c.Publish(ctx, script.ID, "vabbit deploy"); err != nil {
				return res, fmt.Errorf("publish: %w", err)
			}
		}
	} else {
		fmt.Fprintln(o.Out, "  up to date")
	}
	if h := script.Hostname(); h != "" {
		res.URL = "https://" + h
	}
	return res, nil
}

// HasAdminToken reports whether the network is deployed with an admin token.
func HasAdminToken(ctx context.Context, c *bunny.Client, n config.Network) (bool, error) {
	script, err := c.FindScript(ctx, n.ScriptName)
	if errors.Is(err, bunny.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	names, err := c.SecretNames(ctx, script.ID)
	return names["ADMIN_TOKEN_SHA256"], err
}

// Destroy deletes the edge script (with its pull zone) and the storage zone.
// Every device in the network loses its control plane; tunnels stop updating.
func Destroy(ctx context.Context, c *bunny.Client, n config.Network, out io.Writer) error {
	if s, err := c.FindScript(ctx, n.ScriptName); err == nil {
		if err := c.DeleteScript(ctx, s.ID); err != nil {
			return fmt.Errorf("delete edge script: %w", err)
		}
		fmt.Fprintf(out, "  deleted edge script %s\n", n.ScriptName)
	} else if !errors.Is(err, bunny.ErrNotFound) {
		return err
	}
	if z, err := c.FindStorageZone(ctx, n.StorageZone); err == nil {
		if err := c.DeleteStorageZone(ctx, z.ID); err != nil {
			return fmt.Errorf("delete storage zone: %w", err)
		}
		fmt.Fprintf(out, "  deleted storage zone %s\n", n.StorageZone)
	} else if !errors.Is(err, bunny.ErrNotFound) {
		return err
	}
	return nil
}

// adminTokenID is a short public id of the admin token hash, so you can tell
// which token is live (e.g. after a rotation) without exposing anything.
func adminTokenID(hash string) string { return fingerprint("admin:" + hash) }

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
