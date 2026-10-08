// edgeguard-deploy creates and updates EdgeGuard networks on bunny.net from
// a TOML file.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"edgeguard-deploy/edgescript"
	"edgeguard-deploy/internal/bunny"
	"edgeguard-deploy/internal/config"
	"edgeguard-deploy/internal/deploy"
)

const usage = `edgeguard-deploy: run EdgeGuard networks on bunny.net from a config file

  edgeguard-deploy init                 write an example edgeguard.toml
  edgeguard-deploy plan                 show what apply would change (changes nothing)
  edgeguard-deploy apply                create or update every network in the file
  edgeguard-deploy status               show each network's URL and health
  edgeguard-deploy rotate-admin -n NAME replace a network's admin token
  edgeguard-deploy destroy -n NAME      delete a network's edge script and storage

Common flags: -f FILE (default edgeguard.toml), -n NAME (only this network).
The Bunny API key is read from $BUNNY_API_KEY (or the variable named by
api_key_env in the file).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "init":
		err = cmdInit(args)
	case "plan":
		err = cmdApply(ctx, args, true)
	case "apply":
		err = cmdApply(ctx, args, false)
	case "status":
		err = cmdStatus(ctx, args)
	case "rotate-admin":
		err = cmdRotate(ctx, args)
	case "destroy":
		err = cmdDestroy(ctx, args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type common struct {
	file, network, script string
}

func commonFlags(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.file, "f", "edgeguard.toml", "config file")
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
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	file := fs.String("f", "edgeguard.toml", "file to write")
	fs.Parse(args)
	fh, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fh.WriteString(config.Example); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Edit it, set BUNNY_API_KEY, then run: edgeguard-deploy plan\n", *file)
	return nil
}

func scriptCode(f config.File, override string) (string, error) {
	path := override
	if path == "" {
		path = f.Script
	}
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
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	c := commonFlags(fs)
	fs.StringVar(&c.script, "script", "", "built edge script to deploy (default: the one built in)")
	allowCIDR := fs.Bool("allow-cidr-change", false, "allow changing a network's CIDR (strands every enrolled device)")
	tokenFile := fs.String("admin-token-file", "", "also write newly generated admin tokens to this file (mode 0600)")
	noWait := fs.Bool("no-wait", false, "don't wait for the network to answer after publishing")
	fs.Parse(args)
	f, nets, client, err := c.load()
	if err != nil {
		return err
	}
	code, err := scriptCode(f, c.script)
	if err != nil {
		return err
	}
	for _, n := range nets {
		res, err := deploy.Apply(ctx, client, n, code, deploy.Options{DryRun: dry, AllowCIDRChange: *allowCIDR, Out: os.Stdout})
		if err != nil {
			return fmt.Errorf("network %s: %w", n.Name, err)
		}
		if dry {
			continue
		}
		if res.URL != "" {
			fmt.Printf("  url %s\n", res.URL)
			if res.Changed && !*noWait {
				waitHealthy(ctx, res.URL)
			}
		}
		if res.AdminToken != "" {
			fmt.Printf("\n  New admin token for %s (shown once, keep it secret):\n    %s\n", n.Name, res.AdminToken)
			fmt.Printf("  Log in with: edgeguard login --server %s\n\n", res.URL)
			if *tokenFile != "" {
				if err := appendSecret(*tokenFile, fmt.Sprintf("%s %s %s\n", n.Name, res.URL, res.AdminToken)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
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
	fs := flag.NewFlagSet("rotate-admin", flag.ExitOnError)
	c := commonFlags(fs)
	tokenFile := fs.String("admin-token-file", "", "also write the new token to this file (mode 0600)")
	fs.Parse(args)
	if c.network == "" {
		return errors.New("rotate-admin needs -n NETWORK")
	}
	_, nets, client, err := c.load()
	if err != nil {
		return err
	}
	tok, err := deploy.RotateAdmin(ctx, client, nets[0])
	if err != nil {
		return err
	}
	fmt.Printf("New admin token for %s (shown once, keep it secret):\n  %s\n", nets[0].Name, tok)
	fmt.Println("The old token stops working once Bunny has published the change.")
	fmt.Println("Run `edgeguard login` again with the new token. Devices are not affected;")
	fmt.Println("check `edgeguard keys ls` and `edgeguard devices ls` if the old token may have leaked.")
	if *tokenFile != "" {
		return appendSecret(*tokenFile, fmt.Sprintf("%s %s\n", nets[0].Name, tok))
	}
	return nil
}

func cmdDestroy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("destroy", flag.ExitOnError)
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
	return deploy.Destroy(ctx, client, n, os.Stdout)
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
			fmt.Printf("  not answering yet (%s); a new hostname can take a few minutes. Check with: edgeguard-deploy status\n", h)
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func appendSecret(path, line string) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if st, err := fh.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users; chmod 600 it first", path)
	}
	_, err = fh.WriteString(line)
	return err
}
