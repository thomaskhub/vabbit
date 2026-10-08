<p align="center"><img src="docs/brand/vabbit-logo.svg" alt="Vabbit" width="420"></p>

# Vabbit

A tiny, NetBird-style WireGuard network manager whose control plane is a single
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
