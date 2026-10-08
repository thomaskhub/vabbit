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

## Who runs what

| Role | Tool | Does |
|---|---|---|
| [Infrastructure](#infrastructure-deploy-a-network) | `vabbit-deploy` | Creates the network on bunny.net, once per network. Needs the Bunny API key. |
| [Admin](#admin-manage-the-network) | `vabbit` | Logs in with the admin token, hands out setup keys, manages devices and hubs. |
| [Users](#users-connect-a-device) | `vabbit` | Connects a laptop, server or VM with a setup key. Needs root, no admin rights. |

A typical first setup: infrastructure deploys the network, the admin logs in and
[sets up a hub](#setting-up-a-hub), and users join with setup keys.

## Infrastructure: deploy a network

`vabbit-deploy` creates a private storage zone and an edge script per network from a
config file, and is safe to run again after every change ([docs/DEPLOY.md](docs/DEPLOY.md)).

```sh
make deploy && export BUNNY_API_KEY=...          # Bunny: Account settings > API key
./dist/vabbit-deploy init                        # writes vabbit.toml; edit it
./dist/vabbit-deploy plan                        # shows what would change
./dist/vabbit-deploy apply -n home --login        # if you are also the admin (see below)
```

**Where the admin token comes from.** Bunny only ever stores the token's hash, so the
token itself exists in exactly one place: what `apply` hands you the first time it creates
a network (later runs keep the existing token and print nothing).

* **You are the admin too:** `apply -n NAME --login` hands the token straight to
  `vabbit login`, which asks for your master password and stores it encrypted. The
  token is never shown or written in clear. Needs `vabbit` next to `vabbit-deploy` or
  on `PATH`.
* **Someone else is the admin:** `apply` prints the token once on screen, and
  `--admin-token-file admin-tokens.txt` also appends it to that file, which `apply`
  creates for you (mode 0600). Each line is `NETWORK URL TOKEN`:
  ```
  home https://vabbit-home.b-cdn.net vba_3kX…
  ```
  `rotate-admin` takes `--login` and `--admin-token-file` the same way.

In the second case, give the token (or the file) to the admin over a secure channel,
then delete your copy.
The admin logs in with `vabbit login --token-file admin-tokens.txt`, or pastes the token
into `vabbit login --server URL`. A lost token can't be recovered; make a new one with
`vabbit-deploy rotate-admin -n NAME`.

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
| `--admin-token-file FILE` | apply, rotate-admin | | Also append new admin tokens to this file (mode 0600) as `NETWORK URL TOKEN` lines, for `vabbit login --token-file`. |
| `--login` | apply, rotate-admin | off | Save a new admin token straight into your `vabbit login` (encrypted with your master password) instead of printing it. Needs a single network (`-n`). |
| `--no-wait` | apply | off | Don't wait for the network to answer after publishing. |
| `--yes` | destroy | off | Don't ask for confirmation. |

The Bunny API key is read from the environment variable named by `api_key_env` in the
config (default `BUNNY_API_KEY`) and never written to a file.

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

</details>

## Admin: manage the network

The admin logs in once per machine. The login is stored in `~/.config/vabbit/admin.json`
(mode 0600) with the token **encrypted by a master password** you choose at login
(Argon2id + XChaCha20-Poly1305), so a stolen laptop disk or backup doesn't give away
the network. Admin commands ask for the master password each time; scripts can set
`VABBIT_ADMIN_PASSWORD` instead. Keep the login on your own laptop, not on servers.

```sh
vabbit login --server https://mynet.b-cdn.net            # prompts for the token and a master password
vabbit login --token-file admin-tokens.txt               # or from the file vabbit-deploy apply wrote

vabbit keys create                     # one-time setup key for a new device (valid 24h)
vabbit keys create --reusable --ttl 7d --device-ttl 30d  # e.g. for a fleet of short-lived VMs
vabbit devices ls
vabbit devices set <id> --hub=true     # see "Setting up a hub"
vabbit devices rm <id>                 # cut off on its next sync (≤15s)
```

| Command | What it does |
|---|---|
| `vabbit login` | Log in as admin to a network. |
| `vabbit logout` | Forget the admin login on this machine. |
| `vabbit keys create` | Create a setup key for enrolling a device. |
| `vabbit keys ls` | List setup keys. |
| `vabbit keys rm ID` | Delete a setup key. |
| `vabbit devices ls` | List devices. |
| `vabbit devices set ID` | Rename a device, make it a hub, or set when its access expires. |
| `vabbit devices rm ID` | Remove a device; it is cut off on its next sync. |
| `vabbit admin-token` | Print a new admin token and its SHA-256 (only for manual setups). |

**`vabbit login`**

| Flag | Default | Meaning |
|---|---|---|
| `--server URL` | | Control plane URL, e.g. `https://mynet.b-cdn.net`. |
| `--token TOKEN` | prompted | Admin token (`vba_…`). Leave it out to be prompted, so it stays out of shell history. |
| `--no-password` | off | Store the token unencrypted, for unattended machines without anyone to type a password. |
| `--token-file FILE` | | Read the token from a file (mode 0600), or `-` for stdin: just the token, or the lines `vabbit-deploy --admin-token-file` writes. Then the newest token for `--server` is used, and `--server` can be left out if the file names one network. |

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

## Users: connect a device

Get a setup key from the admin, then on the device (Linux, as root):

```sh
sudo VABBIT_SETUP_KEY=vbk_... vabbit up --server https://mynet.b-cdn.net --dry-run   # enroll
sudo cp packaging/vabbit@.service /etc/systemd/system/
sudo systemctl enable --now vabbit@vb0                                               # keep it running
sudo vabbit status
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
* Today devices use the oldest hub only; a second one is a cold spare (switch it
  with `vabbit devices set`).

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
vabbit login --server http://127.0.0.1:8787 --token vba_...
sudo vabbit up --dry-run                 # syncs once and prints the peers instead of starting
```

## Dependencies

The full list with licenses is in [sbom/](sbom/README.md), as CycloneDX SBOMs that CI keeps up to date (`make sbom`).

## License

MIT, see [LICENSE](LICENSE).
