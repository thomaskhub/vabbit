#!/usr/bin/env bash
# Manual hub + failover test with podman/docker, against your real control plane.
# Four Alpine containers: two hubs (hub1, hub2) and two clients (a, b) whose direct path is
# blackholed, so a <-> b traffic can only go through a hub. Then hub1 is stopped and the
# traffic must move to hub2.
#
#   VABBIT_BIN=$PWD/dist/vabbit VABBIT_SERVER=https://<script>.bunny.run scripts/container-hub-e2e.sh
#
# Needs the admin login on this machine (it marks the hubs and creates a setup key; asks
# for the master password, or set VABBIT_ADMIN_PASSWORD). Env: VABBIT_BIN, VABBIT_VERSION,
# ENGINE (podman|docker), KEEP=1.
set -euo pipefail

server=${VABBIT_SERVER:?set VABBIT_SERVER to your control plane URL}
repo=${VABBIT_REPO:-thomaskhub/vabbit}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$engine" ] || { echo "need podman or docker" >&2; exit 1; }
image=docker.io/library/alpine:3.20
tag=$$
names=(hub1 hub2 a b)
c() { echo "vabbit-hub-$1-$tag"; }
net=vabbit-hub-$tag
cache=${XDG_CACHE_HOME:-$HOME/.cache}/vabbit-e2e
mkdir -p "$cache"

cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "kept containers vabbit-hub-*-$tag (remove: $engine rm -f \$($engine ps -aq --filter name=vabbit-hub-.*-$tag))"; return; }
  for n in "${names[@]}"; do "$engine" exec "$(c "$n")" vabbit leave >/dev/null 2>&1 || true; done
  for n in "${names[@]}"; do "$engine" rm -f "$(c "$n")" >/dev/null 2>&1 || true; done
  "$engine" network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
ok() { echo "ok: $*"; }
fail() {
  echo "FAIL: $*" >&2
  for n in "${names[@]}"; do
    echo "--- $n log"; "$engine" exec "$(c "$n")" tail -n 15 /var/log/vabbit.log 2>&1 || true
  done
  echo "--- a status"; "$engine" exec "$(c a)" vabbit status 2>&1 || true
  exit 1
}

# 1. binary
step "binary"
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
if [ -n "${VABBIT_BIN:-}" ]; then
  bin=$VABBIT_BIN
else
  ver=${VABBIT_VERSION:-}
  if [ -z "$ver" ]; then
    rel=$(curl -fsSL "https://api.github.com/repos/$repo/releases?per_page=1") ||
      { echo "could not query GitHub releases; set VABBIT_VERSION or VABBIT_BIN" >&2; exit 1; }
    ver=$(printf '%s' "$rel" | grep -m1 '"tag_name"' | cut -d'"' -f4)
  fi
  bin=$cache/vabbit-$ver-linux-$arch
  if [ ! -x "$bin" ]; then
    base=https://github.com/$repo/releases/download/$ver
    curl -fsSL -o "$bin.tmp" "$base/vabbit-linux-$arch" || { echo "download failed: $base" >&2; exit 1; }
    want=$(curl -fsSL "$base/SHA256SUMS" | awk -v f="vabbit-linux-$arch" '$2==f||$2=="*"f{print $1}')
    echo "$want  $bin.tmp" | sha256sum -c - >/dev/null || { rm -f "$bin.tmp"; echo "checksum mismatch" >&2; exit 1; }
    chmod +x "$bin.tmp"; mv "$bin.tmp" "$bin"
  fi
  echo "using $ver"
fi

# 2. setup key (reusable, replaces same-named devices so reruns need no cleanup)
step "setup key"
key=${VABBIT_SETUP_KEY:-}
if [ -z "$key" ]; then
  key=$(vabbit keys create --reusable --max-uses 4 --ttl 1h --device-ttl 1d --replace | grep -oE 'vbk_[A-Za-z0-9_-]+' | head -n1)
fi
[ -n "$key" ] || { echo "no setup key" >&2; exit 1; }
ok "key"

# 3. containers
step "start containers"
"$engine" network create "$net" >/dev/null
ctr_ip() { "$engine" inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$(c "$1")"; }
vb_ip() { "$engine" exec "$(c "$1")" ip -4 -o addr show dev vb0 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
create() { # NAME [extra run flags...]
  local n=$1; shift
  "$engine" run -d --name "$(c "$n")" --hostname "e2e-$n" \
    --cap-add NET_ADMIN --device /dev/net/tun --security-opt label=disable --network "$net" \
    "$@" "$image" sleep 3600 >/dev/null
  "$engine" cp "$bin" "$(c "$n"):/usr/local/bin/vabbit"   # copy: SELinux blocks executing a bind mount
}
up() { # NAME [vabbit up flags...]
  local n=$1; shift
  "$engine" exec -e VABBIT_SETUP_KEY="$key" -d "$(c "$n")" sh -c \
    "exec vabbit up --server '$server' --name e2e-$n --stun none --tcp-relay off $* >/var/log/vabbit.log 2>&1"
}
wait_vb() { # NAME
  for _ in $(seq 60); do [ -n "$(vb_ip "$1")" ] && return; sleep 1; done
  fail "$1 has no vb0 address"
}
dev_id() { vabbit devices ls | awk -v n="e2e-$1" '$2==n{print $1}' | head -n1; }

for n in "${names[@]}"; do
  # hubs: --privileged only so /proc/sys is writable (the agent switches forwarding on when promoted)
  create "$n" $(case $n in hub*) echo "--privileged" ;; esac)
done

# 4. hubs: enroll with an endpoint, then the admin (this machine) promotes them, hub1 first
step "hubs"
for h in hub1 hub2; do
  up "$h" --endpoint "$(ctr_ip "$h"):51820"
  wait_vb "$h"
  id=$(dev_id "$h"); [ -n "$id" ] || fail "$h not listed by vabbit devices ls"
  vabbit devices set "$id" --hub=true >/dev/null
  ok "$h is a hub ($id)"
  sleep 2   # hub1 must be the older hub
done

# 5. clients: direct path to each other blackholed, so only the hubs can carry the traffic
step "clients"
ip_a=$(ctr_ip a); ip_b=$(ctr_ip b)
"$engine" exec "$(c a)" ip route add blackhole "$ip_b/32"
"$engine" exec "$(c b)" ip route add blackhole "$ip_a/32"
up a; up b
wait_vb a; wait_vb b
va=$(vb_ip a); vb=$(vb_ip b)
echo "a=$va b=$vb (container IPs $ip_a, $ip_b; direct path blocked)"

ping_until() { # FROM TO_IP SECONDS
  local end=$((SECONDS + $3))
  while [ $SECONDS -lt $end ]; do
    "$engine" exec "$(c "$1")" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
msg() { # FROM TO TO_IP TEXT
  "$engine" exec -d "$(c "$2")" sh -c "nc -l -p 9000 >/tmp/msg 2>/dev/null"
  sleep 1
  "$engine" exec "$(c "$1")" sh -c "echo '$4' | nc -w2 $3 9000" >/dev/null 2>&1 || true
  sleep 1
  got=$("$engine" exec "$(c "$2")" cat /tmp/msg 2>/dev/null || true)
  [ "$got" = "$4" ] || fail "expected '$4' on $2, got '$got'"
  ok "'$4'"
}
status_has() { "$engine" exec "$(c a)" vabbit status 2>/dev/null | grep -q "$1"; }

# 6. relay through hub1
step "relay via hub1"
ping_until a "$vb" 120 || fail "a cannot reach b through the hub"
ok "ping a -> b"
status_has 'e2e-hub1.*direct (hub)' || fail "a is not using hub1 as its hub"
status_has 'e2e-b.*relay via hub' || fail "a does not show b as relayed via hub"
ok "a uses hub1, b is relayed"
msg a b "$vb" "hello via hub1"
msg b a "$va" "reply via hub1"

# 7. failover
step "failover: stop hub1"
"$engine" stop -t 1 "$(c hub1)" >/dev/null
start=$SECONDS
ping_until a "$vb" 180 || fail "traffic did not move to hub2 within 180s"
ok "ping a -> b works again after $((SECONDS - start))s"
status_has 'e2e-hub2.*direct (hub)' || fail "a is not using hub2"
ok "a moved to hub2"
msg a b "$vb" "hello via hub2"
msg b a "$va" "reply via hub2"

step "PASS"
