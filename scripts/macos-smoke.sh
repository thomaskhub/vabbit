#!/usr/bin/env bash
# Smoke test for the macOS client, run by hand in CI on a macOS runner (passwordless sudo):
# installs vabbit with install.sh from a local folder, enrolls against the local control
# plane, runs the device as a launchd service and checks the utun address and route, the
# status socket, hosts names, file permissions, down and leave.
#
#   scripts/macos-smoke.sh DIR
#
# DIR holds vabbit-darwin-<arch> and SHA256SUMS. Needs bun and python3.
set -euo pipefail
assets=$1
root=$(cd "$(dirname "$0")/.." && pwd)
server=http://127.0.0.1:8787
iface=vb0
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

fail() { # to stderr, so it also works inside $(...)
  exec >&2
  local msg=$1 tail=""
  [ -f /var/log/vabbit-$iface.log ] && tail="$(printf '\n== vabbit log\n')$(tail -n 25 /var/log/vabbit-$iface.log)"
  printf '%s%s' "$msg" "$tail" | sed 's/%/%25/g' | awk 'BEGIN{ORS="%0A"} {print}' | sed 's/^/::error title=macos smoke::/'
  echo
  echo "FAIL $msg$tail"
  exit 1
}
ok() { echo "ok   $1"; }
check() { local msg=$1; shift; if "$@"; then ok "$msg"; else fail "$msg"; fi; }
waitfor() { # MSG CMD...: up to 30s
  local msg=$1; shift
  for _ in $(seq 60); do "$@" >/dev/null 2>&1 && { ok "$msg"; return; }; sleep 0.5; done
  fail "$msg"
}
v() { # run vabbit; on failure, fail with its output
  local out
  out=$("$@" 2>&1) || fail "$(printf '%s exited %s: %s' "$*" "$?" "$out")"
  printf '%s\n' "$out"
}

(cd "$assets" && python3 -m http.server 8790 --bind 127.0.0.1 >/dev/null 2>&1) &
pids+=($!)
waitfor 'asset server up' curl -fsS http://127.0.0.1:8790/SHA256SUMS
v sudo VABBIT_BASE_URL=http://127.0.0.1:8790 sh "$root/scripts/install.sh" >/dev/null
check 'installer put vabbit in /usr/local/bin' test -x /usr/local/bin/vabbit
vb=/usr/local/bin/vabbit

out=$(v $vb admin-token)
tok=$(grep -oE 'vba_[A-Za-z0-9_-]{43}' <<<"$out")
ADMIN_TOKEN_SHA256=$(grep -oE '[0-9a-f]{64}' <<<"$out")
export ADMIN_TOKEN_SHA256
(cd "$root/edge" && exec bun run dev >/tmp/vabbit-cp.log 2>&1) &
pids+=($!)
waitfor 'control plane up' curl -fsS $server/healthz

export VABBIT_ADMIN_PASSWORD=macos-smoke-test
printf '%s\n' "$tok" | v $vb login --server $server >/dev/null
ok 'admin login'
key() { v $vb keys create | grep -oE 'vbk_[A-Za-z0-9_-]{43}' | head -n 1; }
# A second device, so the Mac has a peer and a name to resolve.
v sudo VABBIT_SETUP_KEY="$(key)" $vb up --server $server --name peer --iface vb9 \
  --state-dir "$(mktemp -d)" --dry-run >/dev/null
v sudo VABBIT_SETUP_KEY="$(key)" $vb up --server $server --name mac-smoke --dry-run >/dev/null
ok 'enrolled'

perm=$(sudo stat -f '%Lp %Su' /var/db/vabbit/$iface.json)
check "device state only readable by root ($perm)" test "$perm" = "600 root"

ip=$(v $vb devices ls | awk '$2 == "mac-smoke" { print $3 }')
peer=$(v $vb devices ls | awk '$2 == "peer" { print $3 }')
v sudo $vb service install --iface $iface >/dev/null
ok 'service installed and started'
waitfor "a utun interface has $ip" sh -c "ifconfig | grep -q 'inet $ip '"
utun=$(ifconfig | awk -v ip="$ip" '/^[a-z]/ { i = $1 } $1 == "inet" && $2 == ip { sub(":", "", i); print i }')
check "MTU 1280 on $utun" sh -c "ifconfig $utun | grep -q 'mtu 1280'"
check "route to the peer $peer goes through $utun" sh -c "route -n get $peer | grep -q 'interface: $utun'"
waitfor 'vabbit status reads the running agent' sh -c "sudo $vb status --iface $iface | grep -q peer"
waitfor 'hosts file has peer.vabbit' grep -q 'peer\.vabbit' /etc/hosts

v sudo $vb down --iface $iface >/dev/null
waitfor 'down stops the service and removes the interface' sh -c "! ifconfig | grep -q 'inet $ip '"
check 'hosts block removed' sh -c "! grep -q 'BEGIN vabbit $iface' /etc/hosts"

v sudo launchctl bootstrap system /Library/LaunchDaemons/com.vabbit.$iface.plist >/dev/null
waitfor 'service starts again' sh -c "ifconfig | grep -q 'inet $ip '"
v sudo $vb leave --iface $iface >/dev/null
ok 'leave'
check 'leave removes the service' test ! -e /Library/LaunchDaemons/com.vabbit.$iface.plist
waitfor 'interface gone after leave' sh -c "! ifconfig | grep -q 'inet $ip '"
check 'device gone from the network' sh -c "! $vb devices ls | grep -q mac-smoke"
echo PASS
