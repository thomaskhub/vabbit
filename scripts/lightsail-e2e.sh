#!/usr/bin/env bash
# Hub-on-the-internet test: creates a small AWS Lightsail VM, installs vabbit on it with
# install.sh, promotes it to hub, then joins a local podman container (behind your home NAT)
# and exchanges a message with the hub over the tunnel. The VM is deleted on exit.
#
#   VABBIT_SERVER=https://<script>.bunny.run scripts/lightsail-e2e.sh
#
# Needs: aws CLI with credentials (Lightsail rights), the admin login on this machine,
# podman or docker, curl. Costs a few cents (nano bundle, billed per hour).
# VMS=2 adds a second VM as backup hub: checks the client reaches it directly across your NAT,
# then stops VM1 (the primary hub) and checks the client moves to VM2 (failover over the internet).
# Env: AWS_REGION (default: aws configure), AZ (default <region>a), BUNDLE (nano_3_0),
#      BLUEPRINT (debian_12), VABBIT_VERSION, VABBIT_BIN (local client binary; the VM always
#      installs the release), YES=1 (skip the confirmation), KEEP=1 (keep the VM),
#      VABBIT_ADMIN_PASSWORD (otherwise asked once), VMS (1 or 2).
# Note: the setup key for the VM is passed in the instance user data (readable on the VM and
# via the Lightsail API). It is single use and expires in 1h.
set -euo pipefail
export AWS_PAGER=""

server=${VABBIT_SERVER:?set VABBIT_SERVER to your control plane URL}
repo=${VABBIT_REPO:-thomaskhub/vabbit}
region=${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}
[ -n "$region" ] || { echo "set AWS_REGION" >&2; exit 1; }
az=${AZ:-${region}a}
bundle=${BUNDLE:-nano_3_0}
blueprint=${BLUEPRINT:-debian_12}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$engine" ] || { echo "need podman or docker" >&2; exit 1; }
image=docker.io/library/alpine:3.20
tag=$(date +%s)
nvm=${VMS:-1}
case $nvm in 1|2) ;; *) echo "VMS must be 1 or 2" >&2; exit 1 ;; esac
ctr=vabbit-e2e-client-$tag
clientname=e2e-client
cache=${XDG_CACHE_HOME:-$HOME/.cache}/vabbit-e2e
work=$(mktemp -d)
mkdir -p "$cache"
created=()
aws_() { aws --region "$region" lightsail "$@"; }
vms=() hubids=() hubvbs=() hubips=()
for i in $(seq "$nvm"); do vms+=("vabbit-e2e-$tag-$i"); done

purge() { vabbit devices ls 2>/dev/null | awk -v n="$1" '$2==n{print $1}' | while read -r id; do vabbit devices rm "$id" >/dev/null 2>&1 || true; done; }
step() { printf '\n== %s\n' "$*"; }
ok() { echo "ok: $*"; }
cleanup() {
  rm -rf "$work"
  "$engine" exec "$ctr" vabbit leave >/dev/null 2>&1 || true
  [ "${KEEP:-0}" = 1 ] || "$engine" rm -f "$ctr" >/dev/null 2>&1 || true
  for n in e2e-hub1 e2e-hub2 $clientname; do purge "$n" 2>/dev/null || true; done
  for vm in "${created[@]}"; do
    if [ "${KEEP:-0}" = 1 ]; then
      echo "kept VM $vm; delete with: aws --region $region lightsail delete-instance --instance-name $vm"
    else
      aws_ delete-instance --instance-name "$vm" --force-delete-add-ons >/dev/null 2>&1 &&
        echo "deleted VM $vm" || echo "COULD NOT DELETE VM $vm: delete it in the Lightsail console" >&2
    fi
  done
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  echo "--- client log"; "$engine" exec "$ctr" tail -n 20 /var/log/vabbit.log 2>&1 || true
  echo "--- client status"; "$engine" exec "$ctr" vabbit status 2>&1 || true
  echo "--- devices"; vabbit devices ls 2>&1 || true
  echo "(VM log: /var/log/vabbit-e2e.log on the VM; rerun with KEEP=1 and open the Lightsail browser SSH)" >&2
  exit 1
}

step "checks"
account=$(aws --region "$region" sts get-caller-identity --query Account --output text) ||
  { echo "aws credentials not working" >&2; exit 1; }
command -v vabbit >/dev/null || { echo "vabbit not in PATH (export PATH=\$PWD/dist:\$PATH)" >&2; exit 1; }
echo "AWS account $account, region $region/$az, $bundle $blueprint, VMs: ${vms[*]}"
if [ "${YES:-0}" != 1 ]; then
  read -r -p "Create a billed Lightsail instance now? [y/N] " a
  [ "$a" = y ] || { echo "aborted"; exit 1; }
fi
if [ -z "${VABBIT_ADMIN_PASSWORD:-}" ]; then
  read -r -s -p "Master password (asked once): " VABBIT_ADMIN_PASSWORD; echo
  export VABBIT_ADMIN_PASSWORD
fi

step "release and binary"
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
ver=${VABBIT_VERSION:-}
if [ -z "$ver" ]; then
  rel=$(curl -fsSL "https://api.github.com/repos/$repo/releases?per_page=1") ||
    { echo "could not query GitHub releases; set VABBIT_VERSION" >&2; exit 1; }
  ver=$(printf '%s' "$rel" | grep -m1 '"tag_name"' | cut -d'"' -f4)
fi
echo "VM installs $ver"
if [ -n "${VABBIT_BIN:-}" ]; then
  bin=$VABBIT_BIN
else
  bin=$cache/vabbit-$ver-linux-$arch
  if [ ! -x "$bin" ]; then
    base=https://github.com/$repo/releases/download/$ver
    curl -fsSL -o "$bin.tmp" "$base/vabbit-linux-$arch" || { echo "download failed: $base" >&2; exit 1; }
    want=$(curl -fsSL "$base/SHA256SUMS" | awk -v f="vabbit-linux-$arch" '$2==f||$2=="*"f{print $1}')
    echo "$want  $bin.tmp" | sha256sum -c - >/dev/null || { rm -f "$bin.tmp"; echo "checksum mismatch" >&2; exit 1; }
    chmod +x "$bin.tmp"; mv "$bin.tmp" "$bin"
  fi
fi

step "remove stale test devices"
for n in e2e-hub1 e2e-hub2 $clientname; do purge "$n"; done   # else a leftover entry is mistaken for the new VM
ok "done"

step "setup keys"
mkkey() {
  local out
  out=$(vabbit keys create --ttl 1h --device-ttl 1d --replace 2>&1) || { echo "vabbit keys create failed (wrong master password?): $out" >&2; return 1; }
  grep -oE 'vbk_[A-Za-z0-9_-]+' <<<"$out" | head -n1
}
hubkeys=()
for _ in "${vms[@]}"; do k=$(mkkey) || exit 1; hubkeys+=("$k"); done
clientkey=$(mkkey) || exit 1
ok "$((nvm + 1)) single-use keys"

step "create VM(s)"
cat >"$work/user-data.tpl" <<'UD'
#!/bin/bash
exec >/var/log/vabbit-e2e.log 2>&1
set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates socat
IP=$(curl -fsS https://checkip.amazonaws.com | tr -d '\n')
cat >/usr/local/bin/e2e-echo.sh <<'EOS'
#!/bin/sh
read l
echo "reply from @NAME@: $l"
EOS
chmod +x /usr/local/bin/e2e-echo.sh
systemd-run --unit=e2e-echo socat TCP-LISTEN:9000,fork,reuseaddr EXEC:/usr/local/bin/e2e-echo.sh
curl -fsSL https://raw.githubusercontent.com/@REPO@/main/scripts/install.sh |
  VABBIT_REPO=@REPO@ VABBIT_VERSION=@VER@ VABBIT_SERVER=@SERVER@ VABBIT_SETUP_KEY=@KEY@ \
  VABBIT_NAME=@NAME@ VABBIT_ENDPOINT="$IP:51820" sh
UD
for i in "${!vms[@]}"; do
  vm=${vms[$i]}; name=e2e-hub$((i + 1))
  sed "s|@REPO@|$repo|g; s|@VER@|$ver|g; s|@SERVER@|$server|g; s|@KEY@|${hubkeys[$i]}|g; s|@NAME@|$name|g" \
    "$work/user-data.tpl" >"$work/user-data-$i.sh"
  aws_ create-instances --instance-names "$vm" --availability-zone "$az" --blueprint-id "$blueprint" \
    --bundle-id "$bundle" --user-data "file://$work/user-data-$i.sh" >/dev/null ||
    { echo "create-instances failed (check AZ/BUNDLE/BLUEPRINT: aws lightsail get-bundles / get-blueprints)" >&2; exit 1; }
  created+=("$vm")
done
for vm in "${vms[@]}"; do
  for _ in $(seq 60); do
    [ "$(aws_ get-instance --instance-name "$vm" --query instance.state.name --output text)" = running ] && break
    sleep 5
  done
  aws_ put-instance-public-ports --instance-name "$vm" \
    --port-infos fromPort=22,toPort=22,protocol=tcp fromPort=51820,toPort=51820,protocol=udp fromPort=443,toPort=443,protocol=tcp >/dev/null
  ip=$(aws_ get-instance --instance-name "$vm" --query instance.publicIpAddress --output text)
  hubips+=("$ip")
  ok "$vm running at $ip"
done

step "wait for the hub(s) to enroll (apt + install, up to 8 min)"
for i in "${!vms[@]}"; do
  hubname=e2e-hub$((i + 1)); line=""
  for _ in $(seq 96); do
    line=$(vabbit devices ls | awk -v n="$hubname" '$2==n{print $1, $3}' | head -n1)
    [ -n "$line" ] && break
    sleep 5
  done
  [ -n "$line" ] || fail "$hubname never enrolled"
  hubids+=("${line% *}"); hubvbs+=("${line#* }")
  vabbit devices set "${line% *}" --hub=true >/dev/null   # hub1 first: the oldest hub is the primary
  ok "$hubname enrolled (${line% *}, ${line#* }) and promoted to hub"
  sleep 3
done
hub_vb=${hubvbs[0]}

step "local client container (behind your NAT)"
"$engine" run -d --name "$ctr" --hostname "$clientname" --cap-add NET_ADMIN --device /dev/net/tun \
  --security-opt label=disable "$image" sleep 3600 >/dev/null
"$engine" cp "$bin" "$ctr:/usr/local/bin/vabbit"
"$engine" exec -e VABBIT_SETUP_KEY="$clientkey" -d "$ctr" sh -c \
  "exec vabbit up --server '$server' --name $clientname >/var/log/vabbit.log 2>&1"
for _ in $(seq 60); do
  "$engine" exec "$ctr" ip -4 -o addr show dev vb0 >/dev/null 2>&1 && break; sleep 1
done
"$engine" exec "$ctr" ip -4 -o addr show dev vb0 >/dev/null 2>&1 || fail "client has no vb0 address"
ok "client up"

step "ping client -> hub ($hub_vb)"
good=0
for _ in $(seq 60); do
  "$engine" exec "$ctr" ping -c1 -W2 "$hub_vb" >/dev/null 2>&1 && { good=1; break; }
  sleep 2
done
[ $good = 1 ] || fail "no reply from the hub over the tunnel (is UDP 51820 open? did the hub start?)"
ok "ping"
"$engine" exec "$ctr" vabbit status | grep -q "e2e-hub1.*direct (hub)" || fail "client does not use hub1 as its hub"
ok "client uses hub1"

step "message client -> hub -> client"
got=$("$engine" exec "$ctr" sh -c "printf 'hello from client\n' | nc -w3 $hub_vb 9000" || true)
[ "$got" = "reply from e2e-hub1: hello from client" ] || fail "expected the hub's echo reply, got '$got'"
ok "$got"

if [ "$nvm" = 2 ]; then
  hub2_vb=${hubvbs[1]}
  step "client -> hub2 ($hub2_vb), directly across your NAT"
  good=0
  for _ in $(seq 60); do
    "$engine" exec "$ctr" ping -c1 -W2 "$hub2_vb" >/dev/null 2>&1 && { good=1; break; }
    sleep 2
  done
  [ $good = 1 ] || fail "no reply from hub2"
  for _ in $(seq 30); do
    "$engine" exec "$ctr" vabbit status | grep -q "e2e-hub2.*direct" && break; sleep 2
  done
  "$engine" exec "$ctr" vabbit status | grep -q "e2e-hub2.*direct" || fail "client has no direct path to hub2"
  got=$("$engine" exec "$ctr" sh -c "printf 'hello hub2\n' | nc -w3 $hub2_vb 9000" || true)
  [ "$got" = "reply from e2e-hub2: hello hub2" ] || fail "expected hub2's echo reply, got '$got'"
  ok "direct path to hub2: $got"

  step "failover over the internet: stop VM1"
  aws_ stop-instance --instance-name "${vms[0]}" --force >/dev/null
  start=$SECONDS
  moved=0
  while [ $((SECONDS - start)) -lt 240 ]; do
    "$engine" exec "$ctr" vabbit status | grep -q "e2e-hub2.*direct (hub)" && { moved=1; break; }
    sleep 3
  done
  [ $moved = 1 ] || fail "client did not move to hub2 within 240s"
  ok "client moved to hub2 after $((SECONDS - start))s"
  "$engine" exec "$ctr" ping -c1 -W3 "$hub2_vb" >/dev/null 2>&1 || fail "no ping to hub2 after failover"
  got=$("$engine" exec "$ctr" sh -c "printf 'after failover\n' | nc -w3 $hub2_vb 9000" || true)
  [ "$got" = "reply from e2e-hub2: after failover" ] || fail "expected hub2's echo reply, got '$got'"
  ok "$got"
fi

step "PASS"
