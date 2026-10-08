# Using Vabbit, start to finish

Pictures of the three common tasks: [connect four nodes](use-cases/1-connect-four-nodes.svg),
[remove a node](use-cases/2-remove-a-node.svg), [change the admin token](use-cases/3-change-admin-token.svg).

An example: one network called `home`, a cloud VM as the hub, a home-lab server,
and a laptop. `$` lines run on the machine named in each heading.

## 1. One-time setup (your laptop + Bunny)

With `vabbit-deploy` ([DEPLOY.md](DEPLOY.md)) this is one command:

```console
$ export BUNNY_API_KEY=...
$ vabbit-deploy init && vabbit-deploy apply
  url https://vabbit-home.b-cdn.net
  New admin token for home (shown once, keep it secret):
    vba_Q3x…k9w
```

Or by hand:

```console
$ vabbit admin-token
Admin token (keep secret, give to `vabbit login`):
  vba_Q3x…k9w

Set this as the edge script secret ADMIN_TOKEN_SHA256:
  a9391d68fc402f0745e9a9801249ab6e5d5f5a2d8ebdc7073d89317912efa352
```

In Bunny: create a Storage zone `home-state`, create an Edge Script from
`edge/dist/edge-script.js`, and set `ADMIN_TOKEN_SHA256` (secret), `STORAGE_ZONE=home-state`,
`STORAGE_ACCESS_KEY` (secret) and `NETWORK_NAME=home`. Say it's served at
`https://home-net.b-cdn.net`.

```console
$ vabbit login --server https://home-net.b-cdn.net
Admin token:
Master password (protects the token on this machine):
Repeat master password:
Logged in to network "home" (100.92.0.0/16). Credentials saved to ~/.config/vabbit/admin.json (encrypted with your master password)
```

## 2. The hub (cloud VM with a public IP)

Open UDP 51820 and TCP 443 in the VM's firewall. Log in as admin there too (a hub
can only be made by the admin), then:

```console
vm$ vabbit login --server https://home-net.b-cdn.net
vm$ sudo vabbit up --endpoint 203.0.113.10:51820 --hub
Enrolled as vm (6bfb0852b06969c6) with address 100.92.194.44
interface vb0 up with 100.92.194.44/16 (hub: true)
TCP relay for UDP-blocked networks on 203.0.113.10:443
```

## 3. Add a machine (home-lab server)

On your laptop, make a one-time key (valid 24h):

```console
$ vabbit keys create
vbk_7hY…2pQ
```

On the server:

```console
lab$ sudo VABBIT_SETUP_KEY=vbk_7hY…2pQ vabbit up --server https://home-net.b-cdn.net
Enrolled as lab (93459a6a15040499) with address 100.92.171.47
candidates: 198.51.100.7:51820,192.168.1.20:51820 (NAT: easy)
peer vm: direct via 203.0.113.10:51820
```

## 4. Add your laptop

Because you're logged in as admin on the laptop, no key is needed:

```console
$ sudo vabbit up
Enrolled as laptop (105888a070d999fb) with address 100.92.173.65
peer vm: direct via 203.0.113.10:51820
peer lab: relay
peer lab: direct via 198.51.100.7:51820      ← hole punched, hub no longer in the path
```

Now `ssh 100.92.171.47` reaches the lab server from anywhere.

## 5. Keep it running after reboots

```console
$ sudo cp packaging/vabbit@.service /etc/systemd/system/
$ sudo systemctl enable --now vabbit@vb0
```

(Settings from the first `up` are remembered, so the service needs no flags.)

## 6. Day to day

```console
$ vabbit devices ls
ID                NAME    IP             ENDPOINT            HUB    STATUS  EXPIRES
6bfb0852b06969c6  vm      100.92.194.44  203.0.113.10:51820  true   online  never
93459a6a15040499  lab     100.92.171.47  -                   false  online  never
105888a070d999fb  laptop  100.92.173.65  -                   false  online  never

$ sudo vabbit status
Device   laptop (105888a070d999fb)
Address  100.92.173.65 in 100.92.0.0/16
To hub   UDP

PEERS
NAME  IP             PATH          ENDPOINT            HANDSHAKE
vm    100.92.194.44  direct (hub)  203.0.113.10:51820  12s ago
lab   100.92.171.47  direct        198.51.100.7:51820  8s ago
```

At a hotel that blocks UDP nothing changes for you; within seconds:

```console
$ sudo vabbit status
To hub   TCP relay 203.0.113.10:443 (UDP blocked)
…
lab   100.92.171.47  relay via hub  …
```

## 7. Who gets access, and for how long

Never give the admin token to other machines. Hand out **setup keys** instead; a
machine uses one once to join and then has its own private device token.

```console
$ vabbit keys create                                  # one machine, key valid 24h
$ vabbit keys create --ttl 2h                         # short-lived key
$ vabbit keys create --reusable --max-uses 5          # up to 5 machines
$ vabbit keys create --reusable --ttl never           # never-expiring key (e.g. for VM images)
$ vabbit keys create --device-ttl 7d                  # the machine itself is cut off after 7 days
$ vabbit keys ls
ID                REUSABLE  USES  KEY EXPIRES       DEVICE ACCESS
0045194ab8977934  true      0/∞   never             7d
fa0772c54dc99bd3  false     0/1   2026-10-08 08:25  until removed
$ vabbit keys rm 0045194ab8977934                     # revoke: no new machines can join with it
```

Revoking a key doesn't remove machines that already joined; remove those with
`devices rm`. You can also give an existing machine an end date, or take it away:

```console
$ vabbit devices set c0257e2673d112c2 --expires 3d
$ vabbit devices set c0257e2673d112c2 --expires never
```

An expired machine drops out of everyone's peer list straight away and its own
agent shuts the interface down on its next sync.

To revoke the admin token itself, run `vabbit admin-token` again, replace the hash
in Bunny and `vabbit login` with the new token. Devices are not affected.

## 8. Removing things

```console
$ vabbit devices rm 93459a6a15040499    # lab is cut off within ~15s, its interface goes down
$ sudo vabbit leave                     # or: a device removes itself
$ vabbit keys ls                        # unused setup keys
$ vabbit keys rm <id>                   # revoke one
$ sudo vabbit down                      # stop the VPN on this machine (stays enrolled)
```

## A second, separate network

Deploy the edge script again with its own storage zone, admin token and
`NETWORK_CIDR` (e.g. `100.93.0.0/16`), then use another interface name per network:

```console
$ sudo VABBIT_SETUP_KEY=vbk_… vabbit up --server https://work-net.b-cdn.net --iface vb1
```
