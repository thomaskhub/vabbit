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

Pictures of the common tasks: [connect four nodes](docs/use-cases/1-connect-four-nodes.svg),
[remove a node](docs/use-cases/2-remove-a-node.svg), [change the admin token](docs/use-cases/3-change-admin-token.svg).
How it works and the security model: [docs/DESIGN.md](docs/DESIGN.md).
Open work: [BACKLOG.md](BACKLOG.md). Picking this up as an AI agent: [AGENT.md](AGENT.md).

## Who runs what

| Role | Tool | Does |
|---|---|---|
| [Admin](#admin-deploy-and-manage-a-network) | `vabbit-deploy`, `vabbit` | Deploys the network on bunny.net, hands out setup keys, manages devices and hubs. |
| [Users](#users-connect-a-device) | `vabbit` | Connect a laptop, server or VM with a setup key. Need root, no admin rights. |

## Admin: deploy and manage a network

One flow, three commands:

```sh
make build && export BUNNY_API_KEY=...   # Bunny: Account settings > API key
./dist/vabbit-deploy init                # writes vabbit.toml, asks for a master password,
                                         # creates the admin token (stored encrypted)
./dist/vabbit-deploy apply               # deploys every network in vabbit.toml
./dist/vabbit keys create                # you're ready: hand out setup keys
```

`init` creates `~/.config/vabbit/admin.json`, which holds the admin token of each of
your networks, **encrypted with your master password** (Argon2id + XChaCha20-Poly1305).
The password is typed as `***`. Bunny only ever gets the token's hash, and nothing is
printed or written in clear. `apply` records each network's URL in the same file, so
`vabbit` admin commands work right away. Every admin command asks for the master
password; scripts can set `VABBIT_ADMIN_PASSWORD` instead.

Change `vabbit.toml` and run `apply` again whenever you like: it only changes what
differs. To add a network, add a `[[network]]` block and `apply`; it gets its own token.

**More admins.** Copy `admin.json` to their `~/.config/vabbit/` (mode 0600) and give
them the master password separately. The file is useless without the password, so it
can travel over normal channels. Everyone shares the token: to remove someone, run
`vabbit-deploy rotate-admin -n NAME` and share the new file. With several networks in
the file, pick one per command with `VABBIT_NETWORK=NAME`.

**Lost the file or password?** Bunny keeps only the hash, so the token can't be recovered.
`vabbit-deploy rotate-admin -n NAME` makes a new one (needs the Bunny API key). Devices
keep working.

### `vabbit-deploy` (needs `BUNNY_API_KEY`)

| Command | What it does |
|---|---|
| `vabbit-deploy init` | Write an example `vabbit.toml` and create your encrypted admin login with a token per network. |
| `vabbit-deploy plan` | Show what `apply` would change, without changing anything. |
| `vabbit-deploy apply` | Create or update every network on Bunny. Safe to run repeatedly. |
| `vabbit-deploy status` | Show each network's URL and whether it answers. |
| `vabbit-deploy rotate-admin -n NAME` | Replace a network's admin token (in your admin login and on Bunny). |
| `vabbit-deploy destroy -n NAME` | Delete a network's edge script and storage zone. Asks you to type the name. |

| Flag | Meaning |
|---|---|
| `-f FILE` | Config file (default `vabbit.toml`). |
| `-n NAME` | Only this network (default: all). Required for `rotate-admin` and `destroy`. |
| `--allow-cidr-change` | `plan`/`apply`: allow changing a network's address range. Every device must re-enroll. |
| `--yes` | `destroy`: don't ask for confirmation. |

Settings live in `vabbit.toml` (see [docs/DEPLOY.md](docs/DEPLOY.md)); the Bunny API key
is read from the environment variable named by `api_key_env` (default `BUNNY_API_KEY`).

### `vabbit` admin commands

```sh
vabbit keys create                         # one machine, key valid 24h
vabbit keys create --reusable --max-uses 5 # up to 5 machines
vabbit keys create --reusable --ttl never  # e.g. baked into VM images
vabbit keys create --device-ttl 7d         # machines joined with it are cut off after 7 days
vabbit keys rm <id>                        # no new machines can join with it
vabbit devices ls
vabbit devices set <id> --expires 3d       # give a machine an end date (or: never)
vabbit devices set <id> --hub=true         # see "Setting up a hub"
vabbit devices rm <id>                     # cut off on its next sync (≤15s)
```

Never put the admin token on other machines; hand out setup keys. A machine uses one
once to join and then has its own device token. Deleting a key doesn't remove machines
that already joined; remove those with `devices rm`. A removed or expired machine drops
out of every peer list at once, and its own agent shuts its interface down.

| Command | What it does |
|---|---|
| `vabbit keys create` | Create a setup key for enrolling a device. |
| `vabbit keys ls` | List setup keys. |
| `vabbit keys rm ID` | Delete a setup key. |
| `vabbit devices ls` | List devices. |
| `vabbit devices set ID` | Rename a device, make it a hub, or set when its access expires. |
| `vabbit devices rm ID` | Remove a device; it is cut off on its next sync. |
| `vabbit login --server URL` | Add a network you didn't deploy with `vabbit-deploy` (asks for its token). |
| `vabbit logout` | Delete the admin login on this machine. |

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

<details>
<summary>Without vabbit-deploy: set it up by hand in the Bunny dashboard</summary>

1. Build the client (`make client`, Go 1.22+) or download a CI artifact.
2. Generate the admin token with `./dist/vabbit admin-token`. Keep the `vba_…` token;
   you'll paste its SHA-256 into Bunny.
3. Create a **Storage zone** (e.g. `mynet-state`). Do **not** connect a pull zone to it.
   Copy its password (FTP & API Access → Password).
4. Create a **standalone Edge Script**, paste `edge/dist/edge-script.js` (from
   `make edge`) or connect this repo with `edge/src/main.ts` as the entry, then set:

   | Name | Kind | Value |
   |---|---|---|
   | `ADMIN_TOKEN_SHA256` | secret | hash printed by `vabbit admin-token` |
   | `STORAGE_ZONE` | variable | `mynet-state` |
   | `STORAGE_ACCESS_KEY` | secret | storage zone password |
   | `STORAGE_HOST` | variable | optional, region host such as `ny.storage.bunnycdn.com` |
   | `NETWORK_CIDR` | variable | optional, default `100.92.0.0/16` (pick a unique one per network) |
   | `NETWORK_NAME` | variable | optional, shown in the CLI |

   The script answers `503 server misconfigured` until all required values are set.
5. `vabbit login --server https://<script hostname>` and paste the token.

</details>

## Users: connect a device

Get a setup key from the admin, then on the device (Linux, amd64 or arm64) install,
join and start the service in one line:

```sh
curl -fsSL https://raw.githubusercontent.com/thomaskhub/vabbit/main/scripts/install.sh |
  sudo VABBIT_SERVER=https://mynet.b-cdn.net VABBIT_SETUP_KEY=vbk_... sh
sudo vabbit status
```

The script downloads the latest release, checks it against the release's `SHA256SUMS`,
installs `/usr/local/bin/vabbit` and the systemd unit, enrolls and runs `vabbit@vb0`.
Without `VABBIT_SETUP_KEY` it only installs. Other settings: `VABBIT_VERSION` (a tag),
`VABBIT_NAME`, `VABBIT_ENDPOINT` (public `HOST:PORT`, e.g. for a hub), `VABBIT_IFACE`.
While the repository is private, pass a GitHub token for both the script and the release:
`curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" … | sudo GITHUB_TOKEN=$GITHUB_TOKEN VABBIT_SERVER=… sh`.

By hand, from a release binary or `make client`:

```sh
sudo VABBIT_SETUP_KEY=vbk_... vabbit up --server https://mynet.b-cdn.net --dry-run   # enroll
sudo cp packaging/vabbit@.service /etc/systemd/system/
sudo systemctl enable --now vabbit@vb0                                               # keep it running
```

`vabbit up` without `--dry-run` enrolls and runs the tunnel in the foreground instead.
Devices need `iproute2` and `/dev/net/tun`; WireGuard itself is built in. Outbound UDP to
STUN servers (default Cloudflare and Google) is used to discover the public address.
To join a second network, use another interface: `--iface vb1` and `vabbit@vb1`.

| Command | What it does |
|---|---|
| `vabbit up` | Enroll this machine (first run) and run the tunnel. |
| `vabbit status` | Show this device, its peers and how each is reached. |
| `vabbit down` | Stop the tunnel; the device stays enrolled. |
| `vabbit leave` | Remove this device from the network and delete its local state. |
| `vabbit version` | Print the version. |

**`vabbit up`**

| Flag | Default | Meaning |
|---|---|---|
| `--server URL` | | Control plane URL. Only needed on the first run. |
| `--setup-key KEY` | `$VABBIT_SETUP_KEY` | Setup key for the first run. The environment variable keeps it out of the process list. Not needed where the admin is logged in. |
| `--name NAME` | hostname | Device name. |
| `--endpoint HOST:PORT` | | Public address other devices can reach this one on. Required for a hub. |
| `--hub` | off | Make this device the hub. Needs `--endpoint` and an admin login on this machine. |
| `--port N` | `51820` | WireGuard UDP listen port. |
| `--interval DURATION` | `15s` | How often to sync with the control plane. |
| `--stun LIST` | Cloudflare and Google | Comma-separated STUN servers (`host:port`), or `none`. |
| `--tcp-relay ADDR` | `:443` | Hubs only: where to serve the TLS relay for UDP-blocked networks, or `off`. |
| `--dry-run` | off | Enroll and sync once, print the peers, and don't start the interface. |
| `--iface NAME` | `vb0` | WireGuard interface. Use a different one per network. |
| `--state-dir DIR` | `/var/lib/vabbit` | Where enrollment state is kept. |

`--endpoint` and `--port` are remembered, so the systemd service picks them up.
`down`, `leave` and `status` take `--iface` and `--state-dir` too.

## Setting up a hub

A hub is an ordinary device with a public IP that relays for devices that can't reach
each other directly (both behind strict NATs) and serves the TCP 443 fallback for
networks that block UDP. Without a hub those devices can't connect.

What it needs, either way:
* A public IPv4 address, with **UDP 51820** and **TCP 443** open in its firewall
  (or `--tcp-relay off` to skip the TCP fallback).
* Only the admin can make a hub, because a hub can see the traffic it relays.
* **Backup hubs:** mark two or more devices as hubs for redundancy. Every device uses
  the oldest one and, if it stops answering for 40s, moves to the next hub that does,
  by itself. It stays there (no flapping back). `vabbit status` shows `direct (hub)`
  for the hub in use and `direct (backup hub)` for the others.

**A. A separate small VM, used only as hub (recommended).** Any VM with 1 vCPU and
512 MB is plenty; the admin token never touches it.

```sh
# On your laptop (admin):
vabbit keys create

# On the VM:
sudo VABBIT_SETUP_KEY=vbk_... vabbit up --server https://mynet.b-cdn.net \
    --endpoint 203.0.113.10:51820 --name hub --dry-run
sudo cp packaging/vabbit@.service /etc/systemd/system/ && sudo systemctl enable --now vabbit@vb0

# On your laptop again:
vabbit devices ls                        # find the VM's id
vabbit devices set <id> --hub=true
```

The VM picks up its new role on the next sync (≤15s) and starts relaying; check with
`sudo vabbit status` on the VM (`Hub true`).

**B. An existing device that already has a public IP**, e.g. a server already in the
network. Tell it its public address, then promote it:

```sh
# On the device:
sudo vabbit up --endpoint 203.0.113.10:51820 --dry-run   # stores the endpoint
sudo systemctl restart vabbit@vb0

# On your laptop (admin):
vabbit devices set <id> --hub=true
```

Keep in mind this machine now carries other devices' relayed traffic, so pick one that
has the bandwidth and that you trust. To stop: `vabbit devices set <id> --hub=false`.

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
echo vba_... | vabbit login --server http://127.0.0.1:8787   # token from vabbit admin-token
sudo vabbit up --dry-run                 # syncs once and prints the peers instead of starting
```

To publish a release, push a tag such as `v0.1.0` (or run the workflow by hand with that tag): [release.yml](.github/workflows/release.yml)
builds the client (Linux amd64/arm64), `vabbit-deploy` (Linux and macOS), the systemd
unit, `install.sh` and `SHA256SUMS`, and attaches them to a GitHub release.

## Dependencies

The full list with licenses is in [sbom/](sbom/README.md), as CycloneDX SBOMs that CI keeps up to date (`make sbom`).

## License

MIT, see [LICENSE](LICENSE).
