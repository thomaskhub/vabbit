# EdgeGuard design

EdgeGuard is a tiny WireGuard management plane. The control plane is a single
Bunny.net Edge Script. **One deployed edge script is one network**: to run two
isolated VPNs, deploy the script twice with different storage zones.

The control plane never carries VPN traffic and never sees a WireGuard private
key. It only hands out IP addresses and tells each device which public keys and
endpoints its peers have.

## Pieces

| Piece | Where | What it does |
|---|---|---|
| `edge/` | Bunny Edge Script (TypeScript) | HTTP API: setup keys, enrollment, device list, peer sync |
| Bunny Storage zone | Bunny | Holds small JSON records (devices, setup keys). No secrets, only hashes |
| `client/` | Go binary `edgeguard` (Linux first) | Admin CLI and the device agent that configures WireGuard |

## Credentials

There are three kinds of token, all 256-bit random values. The server stores
only their SHA-256 hashes and compares in constant time.

1. **Admin token** (`ega_…`). Generated once with `edgeguard admin-token`. Its
   SHA-256 goes into the edge script secret `ADMIN_TOKEN_SHA256`. The plaintext
   lives only in the admin's `~/.config/edgeguard/admin.json` (mode 0600) after
   `edgeguard login`.
2. **Setup key** (`egk_…`). Created by the admin. One-time by default, with an
   expiry (default 24h) and optional use limit. Used once by a device to enroll.
3. **Device token** (`egd_<id>.<secret>`). Returned once at enrollment. The
   device uses it to sync. Deleting the device on the server revokes it.

## Device flow

```
admin:  edgeguard login --server https://net1.b-cdn.net --token ega_...
admin:  edgeguard keys create            -> egk_...
device: sudo edgeguard up --server https://net1.b-cdn.net --setup-key egk_...
          1. generate X25519 keypair locally (private key never leaves the box)
          2. POST /api/v1/enroll {setupKey, name, publicKey, endpoint?, hub?}
             <- device id, VPN IP, device token
          3. create interface eg0, set IP, loop: POST /api/v1/sync every 30s,
             apply the peer list with `wg syncconf`
admin:  edgeguard devices rm <id>        -> device's next sync gets 401,
                                            agent tears the interface down,
                                            every other peer drops it
```

If the admin is logged in on the device itself, `sudo edgeguard up --server …`
mints a one-time setup key automatically.

## Connectivity model

Edge scripts speak HTTP only, so there is no STUN or UDP relay. Instead:

* A device started with `--endpoint host:port` is **public**: others can dial it.
* A device without an endpoint is **behind NAT**: it dials public peers and keeps
  the mapping open with a 25s keepalive.
* Two NATed devices cannot dial each other directly. If the network has a **hub**
  (a public device the admin promoted; devices can never promote themselves,
  because a hub sees relayed traffic in the clear), NATed devices route the whole network
  CIDR through it: the hub peer gets `AllowedIPs = <network CIDR>` and every
  direct peer gets its own `/32`, so WireGuard's longest-prefix match sends
  traffic direct when possible and via the hub otherwise. The hub agent turns on
  IP forwarding for the WireGuard interface.

## Storage

Bunny Storage HTTP API (`AccessKey` header), objects:

```
devices/<id>.json        {id, name, publicKey, ip, endpoint, hub, tokenHash, createdAt, lastSeen}
setup-keys/<sha256>.json {id, hash, reusable, maxUses, uses, expiresAt, createdAt}
```

Notes:
* Storage has no compare-and-swap. IP allocation probes from a hash of the
  device public key, so concurrent enrollments almost never collide; the
  allocator also refuses duplicate public keys.
* `lastSeen` writes are throttled to one per 5 minutes per device.
* Do **not** attach a pull zone to the storage zone; it is private state.

## Hardening

* Request bodies capped at 8 KB; strict JSON validation of every field.
* No CORS, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.
* Tokens only travel in the `Authorization` header (setup key in the body, once).
* The client only applies peer data that stays inside the network CIDR pinned at
  enrollment, so even a compromised control plane cannot route the device's
  other traffic (e.g. `0.0.0.0/0`) into the VPN or inject config lines.
* Client refuses plain `http://` servers except `localhost` (for development).
* Client state file and admin file are written 0600, state dir 0700.
* The client has zero third-party Go dependencies; it uses `crypto/ecdh` for
  X25519 and shells out to `wg` and `ip` (wireguard-tools, iproute2).

## Not in v1

macOS and Windows clients (planned via embedded wireguard-go), NAT traversal
without a hub, ACLs between devices, DNS.
