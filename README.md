# EdgeGuard

A tiny, NetBird-style WireGuard network manager whose control plane is a single
[Bunny.net Edge Script](https://bunny.net/edge-scripting/). **One edge script = one
network.** Want separate VPNs? Deploy the script again with another storage zone.

* The control plane (~400 lines of TypeScript) hands out IPs and peer lists. It never
  sees a WireGuard private key and never carries traffic.
* The client is one static Go binary with zero third-party dependencies: an admin CLI
  and a device agent. Linux today; macOS and Windows are next.
* Tokens are 256-bit random values stored only as SHA-256 hashes.

See [docs/DESIGN.md](docs/DESIGN.md) for how it works and the security model.

## 1. Deploy a network (once per network)

1. Build the client (`make client`, Go 1.22+) or download a CI artifact.
2. Generate the admin token:
   ```sh
   ./dist/edgeguard admin-token
   ```
   Keep the `ega_…` token. You'll paste its SHA-256 into Bunny.
3. In Bunny: create a **Storage zone** (e.g. `mynet-state`). Do **not** connect a pull
   zone to it. Copy its password (FTP & API Access → Password).
4. In Bunny: create a **standalone Edge Script**, paste `edge/dist/edge-script.js`
   (from `make edge`) or connect this repo with `edge/src/main.ts` as the entry, then set:

   | Name | Kind | Value |
   |---|---|---|
   | `ADMIN_TOKEN_SHA256` | secret | hash printed by `edgeguard admin-token` |
   | `STORAGE_ZONE` | variable | `mynet-state` |
   | `STORAGE_ACCESS_KEY` | secret | storage zone password |
   | `STORAGE_HOST` | variable | optional, region host such as `ny.storage.bunnycdn.com` |
   | `NETWORK_CIDR` | variable | optional, default `100.92.0.0/16` (pick a unique one per network) |
   | `NETWORK_NAME` | variable | optional, shown in the CLI |

   The script answers `503 server misconfigured` until all required values are set.

## 2. Log in and add devices

```sh
edgeguard login --server https://mynet.b-cdn.net      # prompts for the ega_ token

# A machine with a public IP that relays for devices behind NAT. Only the admin
# can make a hub (it sees relayed traffic), so do this where you're logged in:
sudo edgeguard up --endpoint 203.0.113.10:51820 --hub

# Any other machine where you're not logged in as admin:
edgeguard keys create                                 # prints a one-time egk_ key (24h)
sudo EDGEGUARD_SETUP_KEY=egk_... edgeguard up --server https://mynet.b-cdn.net
```

On a machine where you're logged in as admin, `sudo edgeguard up` mints its own
one-time key. Devices need `wireguard-tools` and `iproute2`, plus the WireGuard
kernel module (or `wireguard-go` on PATH as a fallback).

To keep it running: `sudo cp packaging/edgeguard@.service /etc/systemd/system/ &&
sudo systemctl enable --now edgeguard@eg0` after the first enrollment.

## 3. Manage

```sh
edgeguard devices ls
edgeguard devices rm <id>         # device is cut off on its next sync (≤30s)
edgeguard devices set <id> --hub=true
edgeguard keys ls / keys rm <id>
sudo edgeguard status
sudo edgeguard leave              # a device removes itself
```

## Connectivity

There is no NAT hole punching. Devices started with `--endpoint` are reachable
directly; devices behind NAT reach those directly and reach each other through the
hub. Without a hub, two NATed devices can't talk to each other.

## Development

```sh
make test                                   # edge (bun test) + client (go test)
sudo ./scripts/e2e-netns.sh                 # real tunnels between 3 network namespaces
cd edge && ADMIN_TOKEN_SHA256=<hash> bun run dev   # local control plane on :8787, in memory
edgeguard login --server http://127.0.0.1:8787 --token ega_...
sudo edgeguard up --dry-run --once          # prints the WireGuard config instead of applying it
```
