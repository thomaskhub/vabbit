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
          2. POST /api/v1/enroll {setupKey, name, publicKey, endpoint?}
             <- device id, VPN IP, device token
          3. start embedded WireGuard on eg0, set IP, loop: POST /api/v1/sync every 15s,
             STUN + hole punch towards every peer (see below)
admin:  edgeguard devices rm <id>        -> device's next sync gets 401,
                                            agent tears the interface down,
                                            every other peer drops it
```

If the admin is logged in on the device itself, `sudo edgeguard up --server …`
mints a one-time setup key automatically.

## Connectivity model (NAT traversal)

Edge scripts speak HTTP only, so the control plane is the rendezvous point
and devices do the punching themselves.

1. **One socket.** The agent embeds userspace WireGuard (wireguard-go) and
   wraps its UDP socket so STUN packets share it (STUN carries a magic cookie
   at byte 4, WireGuard packets never do). The mapping a STUN server sees is
   therefore exactly the NAT mapping WireGuard traffic uses.
2. **Candidates.** Every sync the agent asks two STUN servers for its mapped
   address and reports it, plus its LAN addresses, as `candidates`. Different
   answers from the two servers mean a symmetric NAT (logged; punching will
   likely fail and the hub carries the traffic).
3. **Punching.** For each peer without a live session the agent points the
   WireGuard endpoint at the peer's next candidate every 10s and forces a
   handshake. Both sides do this at once, so each side's outbound packet opens
   the mapping the other side's packet needs: UDP hole punching. Peers behind
   the same public IP try LAN addresses first. Once a handshake succeeds,
   WireGuard roaming keeps the endpoint current and keepalives (25s) hold the
   NAT mapping open.
4. **Relay fallback.** A **hub** is a device with a public endpoint that the
   admin promoted (devices can never promote themselves, because a hub sees
   relayed traffic in the clear). Every non-hub device routes the whole network
   CIDR to the hub. A peer only gets its own `/32` once a direct handshake is
   fresh (<3 min), so traffic goes via the hub until the punch works and
   moves to the direct path the moment it does (longest-prefix match). If a
   direct session dies, the `/32` is withdrawn and traffic falls back to the
   hub while punching resumes. The hub turns on IP forwarding on its
   interface only.
5. **No hub?** Then every peer keeps its `/32` and works only where a direct
   path can be punched.

`scripts/e2e-nat.sh` tests this with real tunnels: two laptops behind separate
emulated home routers (MASQUERADE plus an inbound firewall) connect directly;
with port-randomising ("symmetric") NATs they fall back to the hub.

## Storage

Bunny Storage HTTP API (`AccessKey` header), objects:

```
devices/<id>.json        {id, name, publicKey, ip, endpoint, candidates, hub, tokenHash, createdAt, lastSeen}
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
* Keys and addresses from the server are validated strictly (canonical
  base64, inside the pinned CIDR, no duplicates) before reaching WireGuard.
* The client only applies peer data that stays inside the network CIDR pinned at
  enrollment, so even a compromised control plane cannot route the device's
  other traffic (e.g. `0.0.0.0/0`) into the VPN or inject config lines.
* Client refuses plain `http://` servers except `localhost` (for development).
* Client state file and admin file are written 0600, state dir 0700.
* The client's only dependency is wireguard-go (pinned, plus golang.org/x
  modules). Keys come from `crypto/ecdh`; on Linux it uses `ip` (iproute2) for
  the address. Candidate addresses from the server must be literal `IP:port`,
  so a hostile server can at most make the device send WireGuard handshakes
  to an address of its choosing.

## Not in v1

macOS and Windows clients (the WireGuard part is already portable; address
and route setup is Linux-only), IPv6 candidates, ACLs between devices, DNS.
