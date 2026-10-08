#!/usr/bin/env bash
# End-to-end test with real WireGuard tunnels between three Linux network
# namespaces: a hub with a public endpoint and two devices "behind NAT".
# Needs root, iproute2, wireguard-tools, ping, openssl, bun and go. Uses the
# wireguard kernel module, or wireguard-go on PATH when the module is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
W=$(mktemp -d)
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  sleep 1
  for n in hub lap phone; do ip netns del "eg-$n" 2>/dev/null || true; ip link del "r-$n" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT

(cd client && go build -o "$W/edgeguard" ./cmd/edgeguard)
EG="$W/edgeguard"
export XDG_CONFIG_HOME="$W/cfg" SSL_CERT_FILE="$W/cert.pem"

sysctl -qw net.ipv4.ip_forward=1
i=1
for n in hub lap phone; do
  ip netns add "eg-$n"
  ip link add "r-$n" type veth peer name "v-$n"
  ip link set "v-$n" netns "eg-$n"
  ip addr add "10.10.$i.1/24" dev "r-$n"; ip link set "r-$n" up
  ip -n "eg-$n" addr add "10.10.$i.2/24" dev "v-$n"
  ip -n "eg-$n" link set "v-$n" up; ip -n "eg-$n" link set lo up
  ip -n "eg-$n" route add default via "10.10.$i.1"
  i=$((i + 1))
done

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=cp \
  -addext "subjectAltName=IP:10.10.1.1" -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
out=$("$EG" admin-token)
TOKEN=$(grep -o 'ega_[A-Za-z0-9_-]*' <<<"$out")
HASH=$(tail -1 <<<"$out" | tr -d ' ')
(cd edge && ADMIN_TOKEN_SHA256=$HASH HOST=10.10.1.1 PORT=8787 TLS_CERT=$W/cert.pem TLS_KEY=$W/key.pem \
  exec bun run src/dev.ts >"$W/server.log" 2>&1) &
PIDS+=($!)
sleep 1
SRV=https://10.10.1.1:8787
"$EG" login --server $SRV --token "$TOKEN"

agent() { # name, extra args...
  local n=$1; shift
  ip netns exec "eg-$n" env PATH="$PATH" SSL_CERT_FILE="$SSL_CERT_FILE" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    "$EG" up --name "$n" --iface "eg$n" --state-dir "$W/s-$n" --interval 5s "$@" >>"$W/$n.log" 2>&1 &
  PIDS+=($!)
}
# The hub enrolls through the admin login on "its" machine; the others use setup keys.
agent hub --server $SRV --endpoint 10.10.1.2:51820 --hub
sleep 2
for n in lap phone; do EDGEGUARD_SETUP_KEY=$("$EG" keys create 2>/dev/null) agent "$n" --server $SRV; done
sleep 6
"$EG" devices ls

ipof() { "$EG" devices ls | awk -v n="$1" '$2==n{print $3}'; }
ping_ok() { ip netns exec "eg-$1" ping -c2 -W2 "$2" >/dev/null && echo "ok   $1 -> $2" || { echo "FAIL $1 -> $2"; cat "$W"/*.log; exit 1; }; }
ping_ok lap "$(ipof hub)"
ping_ok lap "$(ipof phone)"   # NAT to NAT, through the hub
ping_ok phone "$(ipof lap)"

"$EG" devices rm "$("$EG" devices ls | awk '$2=="phone"{print $1}')" >/dev/null
sleep 7
if ip -n eg-phone link show egphone >/dev/null 2>&1; then echo "FAIL removed device still has its interface"; exit 1; fi
grep -q "removed from the network" "$W/phone.log" && echo "ok   removed device tore down its interface"
echo PASS
