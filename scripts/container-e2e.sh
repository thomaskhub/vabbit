#!/usr/bin/env bash
# Manual end-to-end test: two small Alpine containers join your real Vabbit network,
# then exchange messages over the tunnel (ping + TCP via nc, both directions).
#
#   VABBIT_SERVER=https://<your-script>.b-cdn.net scripts/container-e2e.sh
#
# Setup key: VABBIT_SETUP_KEY (reusable, 2+ uses), or leave unset and the script runs
# `vabbit keys create --reusable` with the admin login on this machine.
# Env: VABBIT_VERSION (default: latest release incl. pre-releases), ENGINE (podman|docker),
#      KEEP=1 (leave containers running), VABBIT_BIN (use a local linux binary instead).
set -euo pipefail

server=${VABBIT_SERVER:?set VABBIT_SERVER to your control plane URL}
repo=${VABBIT_REPO:-thomaskhub/vabbit}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$engine" ] || { echo "need podman or docker" >&2; exit 1; }
image=docker.io/library/alpine:3.20
tag=$$
names=(vabbit-e2e-a-$tag vabbit-e2e-b-$tag)
cache=${XDG_CACHE_HOME:-$HOME/.cache}/vabbit-e2e
mkdir -p "$cache"

cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "kept: ${names[*]} (remove with: $engine rm -f ${names[*]})"; return; }
  "$engine" rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; for n in "${names[@]}"; do echo "--- $n log"; "$engine" exec "$n" tail -n 30 /var/log/vabbit.log 2>&1 || true; done; exit 1; }

# 1. binary
step "binary"
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
if [ -n "${VABBIT_BIN:-}" ]; then
  bin=$VABBIT_BIN
else
  ver=${VABBIT_VERSION:-}
  if [ -z "$ver" ]; then
    rel=$(curl -fsSL "https://api.github.com/repos/$repo/releases?per_page=1")
    ver=$(printf '%s' "$rel" | grep -m1 '"tag_name"' | cut -d'"' -f4)
  fi
  [ -n "$ver" ] || { echo "could not find a release" >&2; exit 1; }
  bin=$cache/vabbit-$ver-linux-$arch
  if [ ! -x "$bin" ]; then
    base=https://github.com/$repo/releases/download/$ver
    curl -fsSL -o "$bin.tmp" "$base/vabbit-linux-$arch"
    want=$(curl -fsSL "$base/SHA256SUMS" | awk -v f="vabbit-linux-$arch" '$2==f||$2=="*"f{print $1}')
    echo "$want  $bin.tmp" | sha256sum -c - >/dev/null || { rm -f "$bin.tmp"; echo "checksum mismatch" >&2; exit 1; }
    chmod +x "$bin.tmp"; mv "$bin.tmp" "$bin"
  fi
  echo "using $ver"
fi

# 2. setup key
step "setup key"
key=${VABBIT_SETUP_KEY:-}
if [ -z "$key" ]; then
  key=$(vabbit keys create --reusable --max-uses 2 --ttl 1h --device-ttl 1d | grep -oE 'vbk_[A-Za-z0-9_-]+' | head -n1)
fi
[ -n "$key" ] || { echo "no setup key" >&2; exit 1; }
echo "ok"

# 3. containers
step "start containers"
for i in 0 1; do
  n=${names[$i]}
  "$engine" run -d --name "$n" --hostname "e2e-$([ $i = 0 ] && echo a || echo b)-$tag" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$bin:/usr/local/bin/vabbit:ro" "$image" sleep 3600 >/dev/null
  "$engine" exec -e VABBIT_SETUP_KEY="$key" -d "$n" sh -c \
    "exec vabbit up --server '$server' --name e2e-$([ $i = 0 ] && echo a || echo b)-$tag >/var/log/vabbit.log 2>&1"
done

ipof() { "$engine" exec "$1" ip -4 -o addr show dev vb0 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
for n in "${names[@]}"; do
  for _ in $(seq 60); do [ -n "$(ipof "$n")" ] && break; sleep 1; done
  [ -n "$(ipof "$n")" ] || fail "$n has no vb0 address"
done
ip_a=$(ipof "${names[0]}"); ip_b=$(ipof "${names[1]}")
echo "a=$ip_a b=$ip_b"

# 4. tunnel
step "ping a -> b"
ok=0
for _ in $(seq 40); do
  "$engine" exec "${names[0]}" ping -c1 -W2 "$ip_b" >/dev/null 2>&1 && { ok=1; break; }
  sleep 2
done
[ $ok = 1 ] || fail "no reply over the tunnel (same-LAN peers may need a hub: vabbit devices set <id> --hub=true)"
echo "ok"

# 5. messages
msg() { # FROM_IDX TO_IDX TO_IP TEXT
  local from=${names[$1]} to=${names[$2]} text=$4
  "$engine" exec -d "$to" sh -c "nc -l -p 9000 >/tmp/msg 2>/dev/null"
  sleep 1
  "$engine" exec "$from" sh -c "echo '$text' | nc -w2 $3 9000" >/dev/null 2>&1 || true
  sleep 1
  got=$("$engine" exec "$to" cat /tmp/msg 2>/dev/null || true)
  [ "$got" = "$text" ] || fail "expected '$text' on $to, got '$got'"
  echo "ok: '$text'"
}
step "messages over vabbit"
msg 0 1 "$ip_b" "hello from a"
msg 1 0 "$ip_a" "hello from b"

step "PASS"
