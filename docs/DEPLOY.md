# Deploying networks with `vabbit-deploy`

`vabbit-deploy` sets up everything on bunny.net from one TOML file: a private
storage zone and an edge script per network, with all variables and secrets, then
publishes it. Run it again whenever you like; it only changes what differs.

## Setup

```console
$ make deploy                         # builds dist/vabbit-deploy with the edge script inside
$ export BUNNY_API_KEY=...            # bunny.net > Account settings > API key
$ vabbit-deploy init               # writes vabbit.toml
```

```toml
api_key_env = "BUNNY_API_KEY"          # the variable's name, never the key

[[network]]
name = "home"
cidr = "100.92.0.0/16"
storage_region = "DE"                  # DE, NY, LA or SG

[[network]]
name = "work"
cidr = "100.93.0.0/16"
```

| Setting | Default | Meaning |
|---|---|---|
| `name` | required | Network name, also used for the Bunny resource names |
| `cidr` | `100.92.0.0/16` | VPN addresses. Can't change once devices exist |
| `storage_region` | `DE` | Main region of the storage zone |
| `replication_regions` | none | Extra storage regions, e.g. `["NY"]` |
| `script_name` | `vabbit-<name>` | Edge script name, also its `*.b-cdn.net` hostname |
| `storage_zone` | `vabbit-<name>-state` | Storage zone name |
| `admin_token_sha256` | generated | Pin the admin token hash yourself instead |
| `script` (top level) | built in | Path to a different `edge-script.js` |

## Commands

```console
$ vabbit-deploy plan               # shows what would change, changes nothing
network home
  would create storage zone vabbit-home-state in DE
  would create edge script vabbit-home with its own pull zone
  ...

$ vabbit-deploy apply
network home
  create storage zone vabbit-home-state in DE
  create edge script vabbit-home with its own pull zone
  set secret STORAGE_ACCESS_KEY
  generate an admin token
  set secret ADMIN_TOKEN_SHA256
  set NETWORK_NAME=home
  ...
  publish
  url https://vabbit-home.b-cdn.net
  healthy

  New admin token for home (shown once, keep it secret):
    vba_...
  Log in with: vabbit login --server https://vabbit-home.b-cdn.net

$ vabbit-deploy status
NETWORK      URL                                      HEALTH
home         https://vabbit-home.b-cdn.net         ok

$ vabbit-deploy rotate-admin -n home   # new admin token; devices keep working
$ vabbit-deploy destroy -n home        # asks you to type the name first
```

`-f FILE` picks another config file and `-n NAME` limits a command to one network.

## In scripts and CI

Every command exits non-zero on failure, so it fits in shell scripts and pipelines.
Admin tokens are printed once, by the `apply` that creates a network and by
`rotate-admin`. If you are the admin, pass `--login` (with `-n NAME`) instead: the token
goes straight into `vabbit login`, encrypted with your master password, and is never
printed. To hand it to someone else, pass `--admin-token-file FILE`: the file is created
(mode 0600) if missing and gets one `NETWORK URL TOKEN` line per new token. The admin
then logs in with `vabbit login --token-file FILE`. `--no-wait` skips the health check after publishing.

## Safety

* The Bunny API key is read only from the environment and is never written anywhere.
  It can do anything on your Bunny account, so keep it out of the config file and
  out of shell history (`read -s BUNNY_API_KEY; export BUNNY_API_KEY`).
* `apply` never prints secret values. It can't read secrets back from Bunny, so it
  stores short fingerprints (`ADMIN_TOKEN_ID`, `STORAGE_KEY_ID`) as plain variables
  to know whether a secret is current. They reveal nothing about the secrets.
* `apply` refuses to change a network's CIDR (every enrolled device pins it) unless you
  pass `--allow-cidr-change`, and refuses to run when the storage zone has a pull zone
  attached, which would make the network's state public.
* Once a network exists, `apply` keeps its admin token. Use `rotate-admin`, or set
  `admin_token_sha256` in the file, to change it.
