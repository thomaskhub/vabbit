<p align="center"><img src="docs/brand/vabbit-logo.svg" alt="Vabbit" width="420"></p>

# Vabbit

A tiny WireGuard mesh VPN manager whose control plane is a single
[Bunny.net Edge Script](https://bunny.net/edge-scripting/). **One edge script = one
network.** Want separate VPNs? Deploy the script again with another storage zone.

* The control plane (~400 lines of TypeScript) hands out IPs and peer lists. It never
  sees a WireGuard private key and never carries traffic.
* The client is one static Go binary: an admin CLI and a device agent with embedded
  WireGuard. Linux today; macOS and Windows are next.
* NAT traversal: devices punch through NATs with STUN and connect directly; when that
  fails (symmetric NAT) traffic falls back to a relay "hub" automatically.
* Works on hotel and guest Wi-Fi that blocks UDP: the device tunnels to the hub over
  TLS on TCP 443 by itself, and goes back to UDP when it can.
* Made for home labs, laptops and cloud VMs: a small cloud VM makes the ideal hub.
* Tokens are 256-bit random values stored only as SHA-256 hashes.

See [docs/USAGE.md](docs/USAGE.md) for a full walkthrough and [docs/DESIGN.md](docs/DESIGN.md) for how it works and the security model.

## 1. Deploy a network (once per network)

The quick way, with a config file and the Bunny API ([docs/DEPLOY.md](docs/DEPLOY.md)):

```sh
make deploy && export BUNNY_API_KEY=...
./dist/vabbit-deploy init      # writes vabbit.toml; edit it
./dist/vabbit-deploy apply     # creates storage + edge script, prints URL and admin token
```

Or by hand in the Bunny dashboard:

1. Build the client (`make client`, Go 1.22+) or download a CI artifact.
2. Generate the admin token:
   ```sh
   ./dist/vabbit admin-token
   ```
   Keep the `vba_…` token. You'll paste its SHA-256 into Bunny.
3. In Bunny: create a **Storage zone** (e.g. `mynet-state`). Do **not** connect a pull
   zone to it. Copy its password (FTP & API Access → Password).
4. In Bunny: create a **standalone Edge Script**, paste `edge/dist/edge-script.js`
   (from `make edge`) or connect this repo with `edge/src/main.ts` as the entry, then set:

   | Name | Kind | Value |
   |---|---|---|
   | `ADMIN_TOKEN_SHA256` | secret | hash printed by `vabbit admin-token` |
   | `STORAGE_ZONE` | variable | `mynet-state` |
   | `STORAGE_ACCESS_KEY` | secret | storage zone password |
   | `STORAGE_HOST` | variable | optional, region host such as `ny.storage.bunnycdn.com` |
   | `NETWORK_CIDR` | variable | optional, default `100.92.0.0/16` (pick a unique one per network) |
   | `NETWORK_NAME` | variable | optional, shown in the CLI |

   The script answers `503 server misconfigured` until all required values are set.

## 2. Log in and add devices

```sh
vabbit login --server https://mynet.b-cdn.net      # prompts for the vba_ token

# Recommended: a machine with a public IP (e.g. a small cloud VM) that relays when a
# direct path can't be punched or UDP is blocked. Open UDP 51820 and TCP 443 in its
# firewall. Only the admin can make a hub (it sees relayed traffic), so do this
# where you're logged in:
sudo vabbit up --endpoint 203.0.113.10:51820 --hub     # --tcp-relay off to skip TCP 443

# Any other machine where you're not logged in as admin:
vabbit keys create                                 # prints a one-time vbk_ key (24h)
sudo VABBIT_SETUP_KEY=vbk_... vabbit up --server https://mynet.b-cdn.net
```

On a machine where you're logged in as admin, `sudo vabbit up` mints its own
one-time key. Devices need `iproute2` and `/dev/net/tun`; WireGuard itself is built in.
Outbound UDP to STUN servers (default Cloudflare and Google, change with `--stun`) is
used to discover the device's public address.

To keep it running: `sudo cp packaging/vabbit@.service /etc/systemd/system/ &&
sudo systemctl enable --now vabbit@vb0` after the first enrollment.

## 3. Manage

```sh
vabbit devices ls
vabbit devices rm <id>         # device is cut off on its next sync (≤15s)
vabbit devices set <id> --hub=true
vabbit keys ls / keys rm <id>
sudo vabbit status
sudo vabbit leave              # a device removes itself
```

## Command reference

### `vabbit` (devices and admin)

Admin commands use the login stored in `~/.config/vabbit/admin.json`. Device commands
(`up`, `down`, `leave`, `status`) need root and keep their state in `/var/lib/vabbit`.

| Command | What it does |
|---|---|
| `vabbit login` | Log in as admin to a network. |
| `vabbit logout` | Forget the admin login. |
| `vabbit admin-token` | Print a new admin token and its SHA-256 (for manual setups without `vabbit-deploy`). |
| `vabbit keys create` | Create a setup key for enrolling a device. |
| `vabbit keys ls` | List setup keys. |
| `vabbit keys rm ID` | Delete a setup key. |
| `vabbit devices ls` | List devices. |
| `vabbit devices rm ID` | Remove a device; it is cut off on its next sync. |
| `vabbit devices set ID` | Rename a device, make it a hub, or set when its access expires. |
| `vabbit up` | Enroll this machine (first run) and run the tunnel. |
| `vabbit down` | Stop the tunnel; the device stays enrolled. |
| `vabbit leave` | Remove this device from the network and delete its local state. |
| `vabbit status` | Show this device, its peers and how each is reached. |
| `vabbit version` | Print the version. |

**`vabbit login`**

| Flag | Default | Meaning |
|---|---|---|
| `--server URL` | | Control plane URL, e.g. `https://mynet.b-cdn.net`. |
| `--token TOKEN` | prompted | Admin token (`vba_…`). Leave it out to be prompted, so it stays out of shell history. |
| `--token-file FILE` | | Read the admin token from a file (must be mode 0600). The file holds just the token, or the `NETWORK URL TOKEN` lines that `vabbit-deploy --admin-token-file` writes; then the newest token for `--server` is used, and `--server` can be left out if the file names one network. |

**`vabbit keys create`**

| Flag | Default | Meaning |
|---|---|---|
| `--reusable` | off | Let the key enroll more than one device. |
| `--max-uses N` | `0` (unlimited) | Limit how often a reusable key can be used. |
| `--ttl DURATION` | `24h` | How long the key can be used, e.g. `2h`, `7d` or `never`. |
| `--device-ttl DURATION` | `never` | Devices enrolled with this key lose access this long after joining, e.g. `7d`. |

**`vabbit devices set ID`**

| Flag | Meaning |
|---|---|
| `--name NAME` | Rename the device. |
| `--hub=true\|false` | Make the device a hub, or stop it being one. A hub needs a public endpoint. |
| `--expires DURATION` | Remove the device's access this long from now (e.g. `7d`), or `never`. |

**`vabbit up`**

| Flag | Default | Meaning |
|---|---|---|
| `--server URL` | | Control plane URL. Only needed on the first run. |
| `--setup-key KEY` | `$VABBIT_SETUP_KEY` | One-time setup key for the first run. The environment variable keeps it out of the process list. Not needed when logged in as admin. |
| `--name NAME` | hostname | Device name. |
| `--endpoint HOST:PORT` | | Public address other devices can reach this one on. Required for a hub. |
| `--hub` | off | Make this device the hub. Needs `--endpoint` and an admin login. |
| `--port N` | `51820` | WireGuard UDP listen port. |
| `--interval DURATION` | `15s` | How often to sync with the control plane. |
| `--stun LIST` | Cloudflare and Google | Comma-separated STUN servers (`host:port`), or `none`. |
| `--tcp-relay ADDR` | `:443` | Hubs only: where to serve the TLS relay for UDP-blocked networks, or `off`. |
| `--dry-run` | off | Enroll and sync once, print the peers, and don't start the interface. |
| `--iface NAME` | `vb0` | WireGuard interface. Use a different one per network. |
| `--state-dir DIR` | `/var/lib/vabbit` | Where enrollment state is kept. |

`--endpoint` and `--port` given on a later run update the stored settings.

**`vabbit down`, `vabbit leave`, `vabbit status`**

| Flag | Default | Meaning |
|---|---|---|
| `--iface NAME` | `vb0` | Which interface (network) to act on. |
| `--state-dir DIR` | `/var/lib/vabbit` | Where enrollment state is kept. |

### `vabbit-deploy` (bunny.net)

The Bunny API key is read from the environment variable named by `api_key_env` in the
config (default `BUNNY_API_KEY`). See [docs/DEPLOY.md](docs/DEPLOY.md).

| Command | What it does |
|---|---|
| `vabbit-deploy init` | Write an example config file. |
| `vabbit-deploy plan` | Show what `apply` would change, without changing anything. |
| `vabbit-deploy apply` | Create or update every network on Bunny. Safe to run repeatedly. |
| `vabbit-deploy status` | Show each network's URL and whether it answers. |
| `vabbit-deploy rotate-admin -n NAME` | Replace a network's admin token and print the new one. |
| `vabbit-deploy destroy -n NAME` | Delete a network's edge script and storage zone. Asks you to type the name. |

| Flag | Commands | Default | Meaning |
|---|---|---|---|
| `-f FILE` | all | `vabbit.toml` | Config file (for `init`: the file to write). |
| `-n NAME` | plan, apply, status, rotate-admin, destroy | all networks | Only this network. Required for `rotate-admin` and `destroy`. |
| `--script FILE` | plan, apply | built in | Deploy this built edge script instead of the bundled one. |
| `--allow-cidr-change` | plan, apply | off | Allow changing a network's CIDR. Every enrolled device must re-enroll. |
| `--admin-token-file FILE` | apply, rotate-admin | | Also append newly generated admin tokens to this file (mode 0600) as `NETWORK URL TOKEN` lines, ready for `vabbit login --token-file`. |
| `--no-wait` | apply | off | Don't wait for the network to answer after publishing. |
| `--yes` | destroy | off | Don't ask for confirmation. |

## Connectivity

Devices behind NAT find their public address with STUN on the WireGuard port, share it
through the edge script, and punch holes to each other, so most home and office
networks connect directly. `sudo vabbit status` shows each peer's path:

```
NAME   IP              PATH           ENDPOINT            HANDSHAKE
hub    100.92.17.149   direct (hub)   203.0.113.10:51820  12s ago
phone  100.92.125.112  direct         192.0.2.10:51820    10s ago
tv     100.92.239.109  relay via hub  198.51.100.4:17577  never
```

When both sides are behind port-randomising (symmetric) NATs, punching can't work and
traffic goes through the hub; the agent keeps trying and switches to direct when it can.
On networks that block UDP entirely, the device notices within seconds and tunnels to
the hub over TCP 443 (`status` shows `To hub   TCP relay …`). Without a hub, neither
fallback exists. Details in [docs/DESIGN.md](docs/DESIGN.md).

## Development

```sh
make test                                   # edge (bun test) + client (go test)
sudo ./scripts/e2e-nat.sh                   # real tunnels: home NATs, symmetric NATs, UDP-blocked hotel
cd edge && ADMIN_TOKEN_SHA256=<hash> bun run dev   # local control plane on :8787, in memory
vabbit login --server http://127.0.0.1:8787 --token vba_...
sudo vabbit up --dry-run                 # syncs once and prints the peers instead of starting
```

## Dependencies

The full list with licenses is in [sbom/](sbom/README.md), as CycloneDX SBOMs that CI keeps up to date (`make sbom`).

## License

MIT, see [LICENSE](LICENSE).
