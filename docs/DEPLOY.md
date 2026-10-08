# `vabbit-deploy` reference

The commands and the normal flow are in the [README](../README.md#admin-deploy-and-manage-a-network).
This page covers the config file and what `apply` does on Bunny.

## vabbit.toml

```toml
api_key_env = "BUNNY_API_KEY"          # the variable's name, never the key

[[network]]
name = "home"
cidr = "100.92.0.0/16"
storage_region = "DE"

[[network]]
name = "work"
cidr = "100.93.0.0/16"
```

| Setting | Default | Meaning |
|---|---|---|
| `api_key_env` (top level) | `BUNNY_API_KEY` | Environment variable holding the Bunny API key |
| `script` (top level) | built in | Path to a different `edge-script.js` |
| `name` | required | Network name, also used for the Bunny resource names |
| `cidr` | `100.92.0.0/16` | VPN addresses, `/8` to `/28`. Can't change once devices exist |
| `storage_region` | `DE` | Main region of the storage zone: `DE`, `NY`, `LA` or `SG` |
| `replication_regions` | none | Extra storage regions, e.g. `["NY"]` (also `SYD`) |
| `script_name` | `vabbit-<name>` | Edge script name, also its `*.b-cdn.net` hostname |
| `storage_zone` | `vabbit-<name>-state` | Storage zone name |

Unknown settings are rejected, so a typo can't silently do nothing.

## What `apply` creates

Per network: a private storage zone, and a standalone edge script with its own pull
zone (which gives it the `*.b-cdn.net` URL). It sets these on the script, then
publishes it:

| Name | Kind | Value |
|---|---|---|
| `ADMIN_TOKEN_SHA256` | secret | SHA-256 of the admin token in your `admin.json` |
| `STORAGE_ACCESS_KEY` | secret | the storage zone's password |
| `NETWORK_NAME`, `NETWORK_CIDR`, `STORAGE_ZONE`, `STORAGE_HOST` | variables | from the config |
| `ADMIN_TOKEN_ID`, `STORAGE_KEY_ID` | variables | short fingerprints of the secrets (see below) |

Each step only runs when something differs, and nothing is published when nothing
changed. `plan` shows the same steps without doing them and doesn't need the master
password.

## Safety

* The Bunny API key is read only from the environment and is never written anywhere.
  It can do anything on your Bunny account, so keep it out of shell history
  (`read -s BUNNY_API_KEY; export BUNNY_API_KEY`).
* `apply` never prints secret values. Bunny doesn't return secrets, so `apply` keeps
  short fingerprints (`ADMIN_TOKEN_ID`, `STORAGE_KEY_ID`) as plain variables to know
  whether a secret is current. They reveal nothing about the secrets.
* `apply` refuses to change a network's CIDR (every enrolled device pins it) unless you
  pass `--allow-cidr-change`, and refuses to run when the storage zone has a pull zone
  attached, which would make the network's state public.
* `apply` never replaces the admin token of a deployed network it has no token for
  (e.g. on another machine without your `admin.json`); it stops and points you to
  copying the file or to `rotate-admin`.
* Every command exits non-zero on failure. In scripts and CI, set
  `VABBIT_ADMIN_PASSWORD` and keep `admin.json` with your CI secrets.
