// Package cli is `vabbit deploy`: it creates and updates Vabbit networks on
// bunny.net from a TOML file.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"vabbit/adminlogin"
	"vabbit/internal/deploy"
	"vabbit/internal/deploy/bunny"
	"vabbit/internal/deploy/config"
	"vabbit/internal/deploy/edgescript"
)

const usage = `vabbit deploy: run Vabbit networks on bunny.net from a config file

  vabbit deploy init                 write vabbit.toml and set up your encrypted admin login
  vabbit deploy plan                 show what apply would change (changes nothing)
  vabbit deploy apply                create or update every network in the file
  vabbit deploy status               show each network's URL and health
  vabbit deploy rotate-admin -n NAME replace a network's admin token
  vabbit deploy destroy -n NAME      delete a network's edge script and storage

Flags: -f FILE (default vabbit.toml), -n NAME (only this network).
The Bunny API key is read from $BUNNY_API_KEY (or the variable named by
api_key_env in the file). Admin tokens are kept in ~/.config/vabbit/admin.json,
encrypted with your master password; the other admin commands use the same file.
`

// Run runs `vabbit deploy ARGS...`.
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch cmd, args := args[0], args[1:]; cmd {
	case "init":
		return cmdInit(args)
	case "plan":
		return cmdApply(ctx, args, true)
	case "apply":
		return cmdApply(ctx, args, false)
	case "status":
		return cmdStatus(ctx, args)
	case "rotate-admin":
		return cmdRotate(ctx, args)
	case "destroy":
		return cmdDestroy(ctx, args)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown deploy command %q (see vabbit deploy help)", cmd)
	}
}

type common struct {
	file, network string
}

func commonFlags(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.file, "f", "vabbit.toml", "config file")
	fs.StringVar(&c.network, "n", "", "only this network")
	return c
}

func (c *common) load() (config.File, []config.Network, *bunny.Client, error) {
	f, err := config.Load(c.file)
	if err != nil {
		return f, nil, nil, err
	}
	nets := f.Networks
	if c.network != "" {
		n, ok := f.Network(c.network)
		if !ok {
			return f, nil, nil, fmt.Errorf("no network %q in %s", c.network, c.file)
		}
		nets = []config.Network{n}
	}
	key := strings.TrimSpace(os.Getenv(f.APIKeyEnv))
	if key == "" {
		return f, nil, nil, fmt.Errorf("set $%s to your Bunny API key (Account settings > API key)", f.APIKeyEnv)
	}
	base := os.Getenv("BUNNY_API_URL") // tests only
	if base == "" {
		base = bunny.DefaultBaseURL
	}
	client, err := bunny.New(base, key)
	return f, nets, client, err
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("deploy init", flag.ExitOnError)
	file := fs.String("f", "vabbit.toml", "file to write")
	fs.Parse(args)
	fh, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := fh.WriteString(config.Example); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	fmt.Printf("Wrote %s.\n\n", *file)
	f, err := config.Load(*file)
	if err != nil {
		return err
	}
	lg, err := openLogin()
	if err != nil {
		return err
	}
	for _, n := range f.Networks {
		if err := lg.ensureToken(n.Name); err != nil {
			return err
		}
	}
	fmt.Printf("\nNext: edit %s, set BUNNY_API_KEY, then run: vabbit deploy apply\n", *file)
	return nil
}

// login is the admin login (~/.config/vabbit/admin.json), opened with the
// master password.
type login struct {
	path string
	pw   []byte
	adminlogin.Login
}

// openLogin opens the admin login, or starts one under a new master password.
func openLogin() (*login, error) {
	path, err := adminlogin.Path()
	if err != nil {
		return nil, err
	}
	lg := &login{path: path}
	if !adminlogin.Exists(path) {
		fmt.Printf("Creating your admin login %s.\n", path)
		lg.pw, err = adminlogin.NewPassword()
		return lg, err
	}
	if lg.pw, err = adminlogin.Password(); err != nil {
		return nil, err
	}
	lg.Login, err = adminlogin.Load(path, lg.pw)
	return lg, err
}

func (lg *login) save() error { return adminlogin.Save(lg.path, lg.Login, lg.pw) }

// ensureToken creates an admin token for a network that has none yet.
func (lg *login) ensureToken(name string) error {
	if _, ok := lg.Get(name); ok {
		return nil
	}
	tok, _, err := adminlogin.NewToken()
	if err != nil {
		return err
	}
	lg.Set(adminlogin.Network{Name: name, Token: tok})
	if err := lg.save(); err != nil {
		return err
	}
	fmt.Printf("Created the admin token for network %s, stored encrypted in %s.\n", name, lg.path)
	return nil
}

func scriptCode(f config.File) (string, error) {
	path := f.Script
	if path == "" {
		if code := edgescript.Code(); code != "" {
			return code, nil
		}
		path = "edge/dist/edge-script.js"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("edge script: %w (build it with `make edge`, or set script in the config)", err)
	}
	return string(b), nil
}

func cmdApply(ctx context.Context, args []string, dry bool) error {
	name := "apply"
	if dry {
		name = "plan"
	}
	fs := flag.NewFlagSet("deploy "+name, flag.ExitOnError)
	c := commonFlags(fs)
	allowCIDR := fs.Bool("allow-cidr-change", false, "allow changing a network's CIDR (strands every enrolled device)")
	fs.Parse(args)
	f, nets, client, err := c.load()
	if err != nil {
		return err
	}
	code, err := scriptCode(f)
	if err != nil {
		return err
	}
	if dry {
		// A plan changes nothing, so it doesn't need the master password.
		for _, n := range nets {
			if _, err := deploy.Apply(ctx, client, n, code, "", deploy.Options{DryRun: true, AllowCIDRChange: *allowCIDR, Out: os.Stdout}); err != nil {
				return fmt.Errorf("network %s: %w", n.Name, err)
			}
		}
		return nil
	}
	lg, err := openLogin()
	if err != nil {
		return err
	}
	for _, n := range nets {
		if err := applyNetwork(ctx, client, lg, n, code, *allowCIDR); err != nil {
			return err
		}
	}
	fmt.Println("\nDone. Manage the network with: vabbit keys create, vabbit devices ls")
	return nil
}

func applyNetwork(ctx context.Context, client *bunny.Client, lg *login, n config.Network, code string, allowCIDR bool) error {
	if _, ok := lg.Get(n.Name); !ok {
		// Never replace the token of a live network by accident: that would
		// lock out whoever holds it.
		has, err := deploy.HasAdminToken(ctx, client, n)
		if err != nil {
			return fmt.Errorf("network %s: %w", n.Name, err)
		}
		if has {
			return fmt.Errorf("network %s is already deployed, but its admin token is not in %s. Copy admin.json from whoever deployed it, or replace the token with: vabbit deploy rotate-admin -n %s", n.Name, lg.path, n.Name)
		}
		if err := lg.ensureToken(n.Name); err != nil {
			return err
		}
	}
	entry, _ := lg.Get(n.Name)
	res, err := deploy.Apply(ctx, client, n, code, adminlogin.Hash(entry.Token), deploy.Options{AllowCIDRChange: allowCIDR, Out: os.Stdout})
	if err != nil {
		return fmt.Errorf("network %s: %w", n.Name, err)
	}
	if res.URL == "" {
		return nil
	}
	fmt.Printf("  url %s\n", res.URL)
	if entry.Server != res.URL {
		entry.Server = res.URL
		lg.Set(entry)
		if err := lg.save(); err != nil {
			return err
		}
	}
	if res.Changed {
		waitHealthy(ctx, res.URL)
	}
	return nil
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deploy status", flag.ExitOnError)
	c := commonFlags(fs)
	fs.Parse(args)
	_, nets, client, err := c.load()
	if err != nil {
		return err
	}
	fmt.Printf("%-12s %-40s %s\n", "NETWORK", "URL", "HEALTH")
	for _, n := range nets {
		s, err := client.FindScript(ctx, n.ScriptName)
		if errors.Is(err, bunny.ErrNotFound) {
			fmt.Printf("%-12s %-40s %s\n", n.Name, "-", "not deployed")
			continue
		} else if err != nil {
			return err
		}
		url := "https://" + s.Hostname()
		fmt.Printf("%-12s %-40s %s\n", n.Name, url, health(ctx, url))
	}
	return nil
}

func cmdRotate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deploy rotate-admin", flag.ExitOnError)
	c := commonFlags(fs)
	fs.Parse(args)
	if c.network == "" {
		return errors.New("rotate-admin needs -n NETWORK")
	}
	f, nets, client, err := c.load()
	if err != nil {
		return err
	}
	code, err := scriptCode(f)
	if err != nil {
		return err
	}
	lg, err := openLogin()
	if err != nil {
		return err
	}
	n := nets[0]
	tok, _, err := adminlogin.NewToken()
	if err != nil {
		return err
	}
	entry, _ := lg.Get(n.Name)
	entry.Name, entry.Token = n.Name, tok
	lg.Set(entry)
	if err := lg.save(); err != nil {
		return err
	}
	fmt.Printf("New admin token for %s stored in %s; deploying it.\n", n.Name, lg.path)
	if err := applyNetwork(ctx, client, lg, n, code, false); err != nil {
		return fmt.Errorf("%w (the new token is saved; run vabbit deploy apply to finish)", err)
	}
	fmt.Println("The old token no longer works. Devices are not affected; check `vabbit keys ls`")
	fmt.Println("and `vabbit devices ls` if the old token may have leaked.")
	return nil
}

func cmdDestroy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deploy destroy", flag.ExitOnError)
	c := commonFlags(fs)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	fs.Parse(args)
	if c.network == "" {
		return errors.New("destroy needs -n NETWORK")
	}
	_, nets, client, err := c.load()
	if err != nil {
		return err
	}
	n := nets[0]
	if !*yes {
		fmt.Printf("This deletes edge script %s and storage zone %s.\nEvery device in %q loses its network. Type the network name to confirm: ", n.ScriptName, n.StorageZone, n.Name)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != n.Name {
			return errors.New("not confirmed, nothing deleted")
		}
	}
	if err := deploy.Destroy(ctx, client, n, os.Stdout); err != nil {
		return err
	}
	// Drop the dead network's token from the admin login.
	if path, err := adminlogin.Path(); err == nil && adminlogin.Exists(path) {
		lg, err := openLogin()
		if err == nil {
			lg.Remove(n.Name)
			err = lg.save()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  note: could not remove %s from the admin login: %v\n", n.Name, err)
		}
	}
	return nil
}

func health(ctx context.Context, url string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url+"/healthz", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unreachable"
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return "ok"
	case http.StatusServiceUnavailable:
		return "misconfigured (503)"
	default:
		return fmt.Sprintf("HTTP %d", res.StatusCode)
	}
}

func waitHealthy(ctx context.Context, url string) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		h := health(ctx, url)
		if h == "ok" {
			fmt.Println("  healthy")
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			fmt.Printf("  not answering yet (%s); a new hostname can take a few minutes. Check with: vabbit deploy status\n", h)
			return
		}
		time.Sleep(3 * time.Second)
	}
}
