# Backlog

Open work for Vabbit, roughly in priority order. Background and past decisions are in
[AGENT.md](AGENT.md); risks and their numbers are in the security report (see AGENT.md).

## Needs the owner

- [ ] **Test against a real Bunny account.** Everything so far ran against a fake Bunny API
      and the local dev server. Run `vabbit deploy init` and `apply` with a real
      `BUNNY_API_KEY`, join two machines plus a hub, and fix whatever breaks. This is the most
      important open item.
- [x] **Make the repo public.** Done by the owner on 2026-10-09; installs need no `GITHUB_TOKEN` now.
- [ ] **First release `v0.1.0`.** Pre-releases `v0.1.0-rc.1` to `rc.4` (rc.3: PRs 1-5 and `vabbit deploy`; rc.4: Windows client; rc.5: macOS client) were published on 2026-10-08
      and its installer and enrollment against the local dev server worked. Tag `v0.1.0` after
      the real Bunny test (push the tag, or run the release workflow by hand with `tag=v0.1.0`;
      agent sessions can't push tags, so they use the hand run via the Actions API).
- [ ] **LICENSE copyright line** says `thomaskhub`; replace with a real name if preferred.

## Security

- [ ] **Per-person admin tokens** (security report risks 1 and 21). Today all admins share one
      token in one encrypted `admin.json`, so removing one admin means `rotate-admin` for all.
      Idea: named admin tokens stored as hashes in Bunny Storage, managed with
      `vabbit admins add/ls/rm`, with the deploy-time token as the bootstrap admin.
- [ ] **Signed releases** (risks 12 and 23). Sign binaries and `SHA256SUMS` with cosign
      (keyless, GitHub OIDC) or minisign, and verify in `install.sh` when the tool is present.
- [ ] **Access rules between devices** (risk 3), e.g. tags plus "laptops may reach lab".
- [ ] **Per-client rate limit** on the control plane (risk 7).
- [ ] **`rotate-admin --revoke-keys`** to delete all setup keys during a rotation (risk 6).
- [ ] Optional: peer list signed by an offline admin key, so a Bunny takeover cannot add
      devices (risk 2).
- [ ] Outside security review before relying on it for anything critical.

## Features

- [ ] **Windows client: test on a real machine.** Built on 2026-10-08 (Wintun adapter, Windows
      service `vabbit-<iface>`, firewall rules, `install.ps1`); CI runs `scripts/windows-smoke.ps1`
      on a Windows runner. Not yet tried by a person, and a Windows device can't be a hub.
- [ ] **macOS client: test on a real Mac.** Built on 2026-10-08 (utun, `ifconfig`/`route`, launchd
      service `com.vabbit.<iface>`, `install.sh`). `scripts/macos-smoke.sh` runs only by hand
      (workflow `macos`), because macOS CI minutes cost 10x; run it sparingly.
- [ ] IPv6 VPN addresses (IPv6 endpoint candidates are done, PR #2).
- [ ] A DNS server for device names. Today names are written to `/etc/hosts` as `<name>.vabbit`
      (PR #4); existing installs need the new `vabbit@.service` for that.
- [ ] `vabbit deploy` support for the Cloudflare Worker + R2 option (PR #5 documents a manual
      deploy only); it has not run on a real Cloudflare account yet either.
- [ ] Concurrent enrollments can still, very rarely, pick the same address (no compare-and-swap
      in storage); a safe fix needs the client to accept an address change on sync.

## Polish

- [ ] **Flaky e2e in CI.** `scripts/e2e-nat.sh` failed twice on 2026-10-08 (commits 93be3bd and
      b64d802, no related code change) and then passed 5 times in a row; it always passes
      locally. Failures now show up as annotations with the end of each agent log, readable via
      `gh api repos/thomaskhub/vabbit/check-runs/<job id>/annotations`. Look there on the next failure.

- [ ] Convert the text in `docs/brand/vabbit-logo.svg` and `vabbit-banner.svg` to outlines so
      it renders the same without the font installed.
