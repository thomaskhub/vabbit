// Command edgeguard is the EdgeGuard admin CLI and device agent.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"edgeguard/internal/agent"
	"edgeguard/internal/api"
	"edgeguard/internal/state"
	"edgeguard/internal/wg"
)

var version = "dev"

const usage = `edgeguard - tiny WireGuard networks managed from a Bunny Edge Script

Admin:
  edgeguard admin-token                       generate an admin token and its SHA-256 for the edge script
  edgeguard login --server URL [--token T]    save admin credentials (prompts for the token if omitted)
  edgeguard logout
  edgeguard keys create [--reusable] [--max-uses N] [--ttl 24h|7d|never] [--device-ttl 30d]
  edgeguard keys ls
  edgeguard keys rm ID
  edgeguard devices ls
  edgeguard devices rm ID
  edgeguard devices set ID [--name NAME] [--hub=true|false] [--expires 7d|never]

Device (Linux, run as root):
  edgeguard up [--server URL] [--setup-key KEY] [--name NAME] [--endpoint HOST:PORT] [--hub]
               [--port 51820] [--iface eg0] [--interval 15s] [--stun host:port,...] [--dry-run]
  edgeguard down [--iface eg0]
  edgeguard leave [--iface eg0]               remove this device from the network
  edgeguard status [--iface eg0]

The setup key can also be passed in EDGEGUARD_SETUP_KEY to keep it out of the process list.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "admin-token":
		err = cmdAdminToken()
	case "login":
		err = cmdLogin(ctx, args)
	case "logout":
		err = cmdLogout()
	case "keys":
		err = cmdKeys(ctx, args)
	case "devices":
		err = cmdDevices(ctx, args)
	case "up":
		err = cmdUp(ctx, args)
	case "down":
		err = cmdDown(args)
	case "leave":
		err = cmdLeave(ctx, args)
	case "status":
		err = cmdStatus(ctx, args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ---- admin -------------------------------------------------------------------

func cmdAdminToken() error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tok := "ega_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(tok))
	fmt.Printf("Admin token (keep secret, give to `edgeguard login`):\n  %s\n\n", tok)
	fmt.Printf("Set this as the edge script secret ADMIN_TOKEN_SHA256:\n  %s\n", hex.EncodeToString(sum[:]))
	return nil
}

func cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "control plane URL, e.g. https://mynet.b-cdn.net")
	token := fs.String("token", "", "admin token (prompted if omitted)")
	fs.Parse(args)
	if *server == "" {
		return errors.New("--server is required")
	}
	if *token == "" {
		fmt.Fprint(os.Stderr, "Admin token: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		*token = strings.TrimSpace(line)
	}
	base, err := api.ValidateServer(*server)
	if err != nil {
		return err
	}
	c, err := api.New(base, *token)
	if err != nil {
		return err
	}
	n, err := c.Network(ctx)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	path, err := state.AdminPath()
	if err != nil {
		return err
	}
	if err := state.Save(path, state.Admin{Server: base, Token: *token}); err != nil {
		return err
	}
	fmt.Printf("Logged in to network %q (%s). Credentials saved to %s\n", n.Name, n.CIDR, path)
	return nil
}

func cmdLogout() error {
	path, err := state.AdminPath()
	if err != nil {
		return err
	}
	return state.Remove(path)
}

func adminClient() (*api.Client, state.Admin, error) {
	var a state.Admin
	path, err := state.AdminPath()
	if err != nil {
		return nil, a, err
	}
	if err := state.Load(path, &a); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, a, errors.New("not logged in; run `edgeguard login --server URL`")
		}
		return nil, a, err
	}
	c, err := api.New(a.Server, a.Token)
	return c, a, err
}

func cmdKeys(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: edgeguard keys create|ls|rm")
	}
	c, _, err := adminClient()
	if err != nil {
		return err
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("keys create", flag.ExitOnError)
		reusable := fs.Bool("reusable", false, "allow the key to enroll more than one device")
		maxUses := fs.Int("max-uses", 0, "limit uses of a reusable key (0 = unlimited)")
		ttlFlag := fs.String("ttl", "24h", "how long the key can be used: e.g. 2h, 7d, or never")
		devTTLFlag := fs.String("device-ttl", "never", "devices enrolled with this key lose access this long after joining, e.g. 7d")
		fs.Parse(args[1:])
		ttl, err := parseLifetime(*ttlFlag)
		if err != nil {
			return fmt.Errorf("--ttl: %w", err)
		}
		devTTL, err := parseLifetime(*devTTLFlag)
		if err != nil {
			return fmt.Errorf("--device-ttl: %w", err)
		}
		k, err := c.CreateSetupKey(ctx, api.SetupKeyOptions{Reusable: *reusable, MaxUses: *maxUses, TTL: ttl, DeviceTTL: devTTL})
		if err != nil {
			return err
		}
		fmt.Println(k.Key)
		devices := "devices keep access until removed"
		if k.DeviceTTLSeconds != nil {
			devices = "devices lose access " + humanDuration(time.Duration(*k.DeviceTTLSeconds)*time.Second) + " after joining"
		}
		fmt.Fprintf(os.Stderr, "id %s, key expires %s, %s. On the device run:\n  sudo EDGEGUARD_SETUP_KEY=%s edgeguard up --server <URL>\n",
			k.ID, whenOrNever(k.ExpiresAt), devices, k.Key)
	case "ls":
		keys, err := c.ListSetupKeys(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tREUSABLE\tUSES\tKEY EXPIRES\tDEVICE ACCESS")
		for _, k := range keys {
			limit := "∞"
			if k.MaxUses > 0 {
				limit = fmt.Sprint(k.MaxUses)
			}
			access := "until removed"
			if k.DeviceTTLSeconds != nil {
				access = humanDuration(time.Duration(*k.DeviceTTLSeconds) * time.Second)
			}
			fmt.Fprintf(w, "%s\t%v\t%d/%s\t%s\t%s\n", k.ID, k.Reusable, k.Uses, limit, whenOrNever(k.ExpiresAt), access)
		}
		w.Flush()
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: edgeguard keys rm ID")
		}
		return c.DeleteSetupKey(ctx, args[1])
	default:
		return fmt.Errorf("unknown keys command %q", args[0])
	}
	return nil
}

func cmdDevices(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: edgeguard devices ls|rm|set")
	}
	c, _, err := adminClient()
	if err != nil {
		return err
	}
	switch args[0] {
	case "ls":
		devs, err := c.ListDevices(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tIP\tENDPOINT\tHUB\tSTATUS\tEXPIRES")
		for _, d := range devs {
			ep := "-"
			if d.Endpoint != nil {
				ep = *d.Endpoint
			}
			status := "offline"
			if t, err := time.Parse(time.RFC3339, d.LastSeen); err == nil {
				if time.Since(t) < 6*time.Minute {
					status = "online"
				} else {
					status = "seen " + t.Local().Format("2006-01-02 15:04")
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\t%s\n", d.ID, d.Name, d.IP, ep, d.Hub, status, whenOrNever(d.ExpiresAt))
		}
		w.Flush()
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: edgeguard devices rm ID")
		}
		if err := c.DeleteDevice(ctx, args[1]); err != nil {
			return err
		}
		fmt.Println("Removed. Other devices drop it on their next sync.")
	case "set":
		if len(args) < 2 {
			return errors.New("usage: edgeguard devices set ID [--name NAME] [--hub=true|false] [--expires 7d|never]")
		}
		fs := flag.NewFlagSet("devices set", flag.ExitOnError)
		name := fs.String("name", "", "new name")
		hub := fs.String("hub", "", "true or false")
		expires := fs.String("expires", "", "remove the device's access this long from now (e.g. 7d), or never")
		fs.Parse(args[2:])
		patch := map[string]any{}
		if *expires != "" {
			d, err := parseLifetime(*expires)
			if err != nil {
				return fmt.Errorf("--expires: %w", err)
			}
			if d == 0 {
				patch["expiresInSeconds"] = nil
			} else {
				patch["expiresInSeconds"] = int(d.Seconds())
			}
		}
		if *name != "" {
			patch["name"] = *name
		}
		switch *hub {
		case "":
		case "true":
			patch["hub"] = true
		case "false":
			patch["hub"] = false
		default:
			return errors.New("--hub must be true or false")
		}
		d, err := c.UpdateDevice(ctx, args[1], patch)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s hub=%v expires=%s\n", d.ID, d.Name, d.Hub, whenOrNever(d.ExpiresAt))
	default:
		return fmt.Errorf("unknown devices command %q", args[0])
	}
	return nil
}

// ---- device agent --------------------------------------------------------------

type deviceFlags struct {
	iface    *string
	stateDir *string
}

func addDeviceFlags(fs *flag.FlagSet) deviceFlags {
	return deviceFlags{
		iface:    fs.String("iface", "eg0", "WireGuard interface name"),
		stateDir: fs.String("state-dir", state.DefaultDir, "where enrollment state is kept"),
	}
}

func (d deviceFlags) path() (string, error) {
	if !wg.ValidIface(*d.iface) {
		return "", fmt.Errorf("invalid interface name %q", *d.iface)
	}
	return state.DevicePath(*d.stateDir, *d.iface), nil
}

var nameRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func defaultName() string {
	h, _ := os.Hostname()
	h = strings.Trim(nameRE.ReplaceAllString(h, "-"), "-._")
	if h == "" {
		return "device"
	}
	if len(h) > 63 {
		h = h[:63]
	}
	return h
}

func cmdUp(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	df := addDeviceFlags(fs)
	server := fs.String("server", "", "control plane URL (only needed for the first run)")
	setupKey := fs.String("setup-key", os.Getenv("EDGEGUARD_SETUP_KEY"), "one-time setup key (first run)")
	name := fs.String("name", "", "device name (default: hostname)")
	endpoint := fs.String("endpoint", "", "public HOST:PORT other devices can reach this one on")
	hub := fs.Bool("hub", false, "make this device the hub that relays for devices behind NAT (needs --endpoint and an admin login)")
	port := fs.Int("port", 0, "WireGuard listen port (default 51820)")
	interval := fs.Duration("interval", 15*time.Second, "how often to sync with the control plane")
	stunFlag := fs.String("stun", "", "comma-separated STUN servers host:port, or \"none\" (default Cloudflare and Google)")
	tcpRelay := fs.String("tcp-relay", ":443", "hubs only: where to serve the TLS relay for devices on UDP-blocked networks (\"off\" to disable)")
	dryRun := fs.Bool("dry-run", false, "enroll/sync once and print the peers instead of starting the interface")
	fs.Parse(args)

	if !*dryRun && os.Geteuid() != 0 {
		return errors.New("must run as root to configure WireGuard (or use --dry-run)")
	}
	if *interval < 5*time.Second {
		return errors.New("--interval must be at least 5s")
	}
	if *endpoint != "" {
		if err := agent.ValidateEndpoint(*endpoint); err != nil {
			return err
		}
	}
	path, err := df.path()
	if err != nil {
		return err
	}

	var dev state.Device
	err = state.Load(path, &dev)
	switch {
	case errors.Is(err, os.ErrNotExist):
		dev, err = enroll(ctx, *server, *setupKey, *name, *endpoint, *port)
		if err != nil {
			return err
		}
		if err := state.Save(path, dev); err != nil {
			return fmt.Errorf("enrolled as %s but could not save state: %w", dev.DeviceID, err)
		}
		fmt.Printf("Enrolled as %s (%s) with address %s\n", dev.Name, dev.DeviceID, dev.IP)
	case err != nil:
		return err
	default:
		if *server != "" {
			if base, err := api.ValidateServer(*server); err != nil || base != dev.Server {
				return fmt.Errorf("this interface is enrolled with %s; use another --iface or `edgeguard leave` first", dev.Server)
			}
		}
		// Flags given on later runs update the stored settings.
		changed := false
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "endpoint":
				dev.Endpoint, changed = *endpoint, true
			case "port":
				dev.ListenPort, changed = *port, true
			}
		})
		if changed {
			if err := state.Save(path, dev); err != nil {
				return err
			}
		}
	}

	c, err := api.New(dev.Server, dev.DeviceToken)
	if err != nil {
		return err
	}
	hubSet := false
	fs.Visit(func(f *flag.Flag) { hubSet = hubSet || f.Name == "hub" })
	if hubSet {
		if err := setHub(ctx, c, dev, *hub); err != nil {
			return err
		}
	}
	if *dryRun {
		return dryRunSync(ctx, c, dev)
	}
	stunServers := agent.DefaultSTUN
	if *stunFlag != "" {
		stunServers = strings.Split(*stunFlag, ",")
	}
	if *stunFlag == "none" {
		stunServers = nil
	}
	err = agent.Run(ctx, agent.Options{
		Iface:        *df.iface,
		Device:       dev,
		Client:       c,
		STUNServers:  stunServers,
		SyncInterval: *interval,
		TCPRelay:     relayListen(*tcpRelay),
		Logf:         func(f string, a ...any) { log.Printf(f, a...) },
	})
	if errors.Is(err, agent.ErrRemoved) {
		_ = state.Remove(path)
		return fmt.Errorf("%v; interface removed and local state cleared", err)
	}
	if err == nil {
		fmt.Println("Interface down.")
	}
	return err
}

// parseLifetime accepts Go durations plus days ("7d", "1d12h") and "never"
// (returned as 0).
func parseLifetime(s string) (time.Duration, error) {
	if s == "never" || s == "0" {
		return 0, nil
	}
	var days time.Duration
	if i := strings.Index(s, "d"); i > 0 {
		n, err := strconv.Atoi(s[:i])
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		days, s = time.Duration(n)*24*time.Hour, s[i+1:]
	}
	var rest time.Duration
	if s != "" {
		var err error
		if rest, err = time.ParseDuration(s); err != nil || rest < 0 {
			return 0, fmt.Errorf("invalid duration %q (use e.g. 2h, 7d or never)", s)
		}
	}
	d := days + rest
	if d < time.Minute {
		return 0, errors.New("must be at least 1m, or never")
	}
	return d, nil
}

func humanDuration(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

func whenOrNever(iso *string) string {
	if iso == nil {
		return "never"
	}
	if t, err := time.Parse(time.RFC3339, *iso); err == nil {
		return t.Local().Format("2006-01-02 15:04")
	}
	return *iso
}

func relayListen(v string) string {
	if v == "off" {
		return ""
	}
	return v
}

// setHub promotes or demotes this device. Only the admin may do that, so it
// uses the admin login on this machine.
func setHub(ctx context.Context, c *api.Client, dev state.Device, hub bool) error {
	if hub && dev.Endpoint == "" {
		return errors.New("--hub needs --endpoint")
	}
	if hub {
		// The server only accepts a hub that has an endpoint on record.
		if _, err := c.Sync(ctx, dev.Endpoint, nil, nil); err != nil {
			return err
		}
	}
	admin, a, err := adminClient()
	if err != nil {
		return fmt.Errorf("--hub needs an admin login on this machine (or run `edgeguard devices set %s --hub=%v` as admin): %w", dev.DeviceID, hub, err)
	}
	if a.Server != dev.Server {
		return errors.New("--hub: admin login is for a different server")
	}
	_, err = admin.UpdateDevice(ctx, dev.DeviceID, map[string]any{"hub": hub})
	return err
}

func enroll(ctx context.Context, server, setupKey, name, endpoint string, port int) (state.Device, error) {
	var dev state.Device
	if server == "" || setupKey == "" {
		// Fall back to the admin login: mint a one-time key for ourselves.
		c, a, err := adminClient()
		if err != nil {
			return dev, errors.New("first run needs --server and --setup-key (or EDGEGUARD_SETUP_KEY), or an admin login")
		}
		if server == "" {
			server = a.Server
		}
		if setupKey == "" {
			if base, _ := api.ValidateServer(server); base != a.Server {
				return dev, errors.New("--setup-key is required for a server you are not logged in to")
			}
			k, err := c.CreateSetupKey(ctx, api.SetupKeyOptions{MaxUses: 1, TTL: 10 * time.Minute})
			if err != nil {
				return dev, fmt.Errorf("creating setup key: %w", err)
			}
			setupKey = k.Key
		}
	}
	base, err := api.ValidateServer(server)
	if err != nil {
		return dev, err
	}
	if name == "" {
		name = defaultName()
	}
	if port == 0 {
		port = 51820
	}
	if port < 1 || port > 65535 {
		return dev, errors.New("--port out of range")
	}
	priv, pub, err := wg.GenerateKey()
	if err != nil {
		return dev, err
	}
	c, err := api.New(base, "")
	if err != nil {
		return dev, err
	}
	res, err := c.Enroll(ctx, api.EnrollRequest{SetupKey: setupKey, Name: name, PublicKey: pub, Endpoint: endpoint})
	if err != nil {
		return dev, fmt.Errorf("enrollment failed: %w", err)
	}
	if res.Device.PublicKey != pub {
		return dev, errors.New("server returned a different public key")
	}
	return state.Device{
		Server:      base,
		DeviceID:    res.Device.ID,
		DeviceToken: res.DeviceToken,
		PrivateKey:  priv,
		Name:        res.Device.Name,
		IP:          res.Device.IP,
		NetworkCIDR: res.Network.CIDR,
		ListenPort:  port,
		Endpoint:    endpoint,
	}, nil
}

// dryRunSync syncs once and prints what the agent would configure.
func dryRunSync(ctx context.Context, c *api.Client, dev state.Device) error {
	pub, err := wg.PublicKey(dev.PrivateKey)
	if err != nil {
		return err
	}
	s, err := c.Sync(ctx, dev.Endpoint, nil, nil)
	if err != nil {
		return err
	}
	n, err := agent.Validate(s, dev.NetworkCIDR, pub)
	if err != nil {
		return fmt.Errorf("rejected control plane data: %w", err)
	}
	fmt.Printf("address %s (hub: %v), %d peer(s)\n", n.Address, n.SelfHub, len(n.Peers))
	for _, p := range n.Peers {
		fmt.Printf("  %-20s %-15s hub=%-5v endpoints=%s\n", p.Name, p.IP, p.Hub, strings.Join(p.Endpoints, ","))
	}
	return nil
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	df := addDeviceFlags(fs)
	fs.Parse(args)
	return wg.Down(*df.iface)
}

func cmdLeave(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("leave", flag.ExitOnError)
	df := addDeviceFlags(fs)
	fs.Parse(args)
	path, err := df.path()
	if err != nil {
		return err
	}
	var dev state.Device
	if err := state.Load(path, &dev); err != nil {
		return err
	}
	c, err := api.New(dev.Server, dev.DeviceToken)
	if err != nil {
		return err
	}
	if err := c.Leave(ctx); err != nil && !errors.Is(err, api.ErrUnauthorized) {
		return err
	}
	_ = wg.Down(*df.iface)
	if err := state.Remove(path); err != nil {
		return err
	}
	fmt.Println("Left the network.")
	return nil
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	df := addDeviceFlags(fs)
	fs.Parse(args)
	path, err := df.path()
	if err != nil {
		return err
	}
	var dev state.Device
	if err := state.Load(path, &dev); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("Not enrolled. Run `sudo edgeguard up --server URL --setup-key KEY`.")
			return nil
		}
		return err
	}
	fmt.Printf("Device   %s (%s)\nServer   %s\nAddress  %s in %s\n", dev.Name, dev.DeviceID, dev.Server, dev.IP, dev.NetworkCIDR)
	if dev.Endpoint != "" {
		fmt.Printf("Endpoint %s\n", dev.Endpoint)
	}
	stats, err := wg.Show(*df.iface)
	if err != nil {
		fmt.Println("Agent    not running:", err)
	}
	c, err := api.New(dev.Server, dev.DeviceToken)
	if err != nil {
		return err
	}
	pub, _ := wg.PublicKey(dev.PrivateKey)
	s, err := c.Sync(ctx, dev.Endpoint, nil, nil)
	if err != nil {
		fmt.Println("Control plane:", err)
		return nil
	}
	n, err := agent.Validate(s, dev.NetworkCIDR, pub)
	if err != nil {
		return err
	}
	fmt.Printf("Hub      %v\n", n.SelfHub)
	if t, err := os.ReadFile(agent.TransportFile(*df.iface)); err == nil && !n.SelfHub {
		fmt.Printf("To hub   %s", t)
	}
	fmt.Print("\nPEERS\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tIP\tPATH\tENDPOINT\tHANDSHAKE")
	for _, p := range n.Peers {
		st, ok := stats[p.PublicKey]
		path, ep, hs := "-", "-", "never"
		if ok {
			alive := !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 3*time.Minute
			switch {
			case alive && p.Hub && !n.SelfHub:
				path = "direct (hub)"
			case alive:
				path = "direct"
			case len(st.AllowedIPs) == 0:
				path = "relay via hub"
			default:
				path = "connecting"
			}
			if st.Endpoint.IsValid() {
				ep = st.Endpoint.String()
			}
			if !st.LastHandshake.IsZero() {
				hs = time.Since(st.LastHandshake).Round(time.Second).String() + " ago"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.IP, path, ep, hs)
	}
	return w.Flush()
}
