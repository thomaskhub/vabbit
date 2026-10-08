#!/usr/bin/env bash
# End-to-end NAT traversal test with real WireGuard tunnels in Linux network
# namespaces:
#
#   lap (192.168.1.2) -- natA --+                +-- hub (203.0.113.10, public)
#                               +-- internet --+-- STUN 9.9.9.9 / 9.9.9.10
#   phone (192.168.1.3) - natB -+                +-- control plane 9.9.9.20
#
# Both laptops sit behind their own NAT router. Modes:
#   cone       Linux MASQUERADE keeps ports, like most home routers: hole
#              punching must give a direct path.
#   symmetric  random ports per destination: punching fails and traffic must
#              fall back to the hub.
#   hotel      lap's network drops all UDP: lap must tunnel to the hub over
#              TLS on TCP 443 on its own.
# Default: all three.
#
# Needs root, iproute2, iptables, ping, openssl, bun and go.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d)
NS=(inet natA natB lap phone hub)
PIDS=()
stop_all() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  pkill -f "$W/" 2>/dev/null || true # agents and STUN servers run from $W
  PIDS=()
}
cleanup() {
  stop_all
  sleep 1
  for n in "${NS[@]}"; do ip netns del "eg-$n" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT

(cd client && go build -o "$W/vabbit" ./cmd/vabbit && go build -o "$W/stunserver" ./tools/stunserver)
EG="$W/vabbit"
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy # everything below is local
x() { local n=$1; shift; ip netns exec "eg-$n" "$@"; }

link() { # nsA ifA addrA nsB ifB addrB
  ip link add "$2" netns "eg-$1" type veth peer name "$5" netns "eg-$4"
  x "$1" ip addr add "$3" dev "$2"; x "$1" ip link set "$2" up
  x "$4" ip addr add "$6" dev "$5"; x "$4" ip link set "$5" up
}

setup() { # nat mode: cone | symmetric
  for n in "${NS[@]}"; do ip netns add "eg-$n"; x "$n" ip link set lo up; done
  link inet i-hub 203.0.113.1/24 hub wan 203.0.113.10/24
  link inet i-natA 198.51.100.1/24 natA wan 198.51.100.10/24
  link inet i-natB 192.0.2.1/24 natB wan 192.0.2.10/24
  link natA lan 192.168.1.1/24 lap eth0 192.168.1.2/24
  link natB lan 192.168.1.1/24 phone eth0 192.168.1.3/24
  for ip in 9.9.9.9 9.9.9.10 9.9.9.20; do x inet ip addr add $ip/32 dev lo; done
  x hub ip route add default via 203.0.113.1
  x natA ip route add default via 198.51.100.1
  x natB ip route add default via 192.0.2.1
  x lap ip route add default via 192.168.1.1
  x phone ip route add default via 192.168.1.1
  local extra=""
  [ "$1" = symmetric ] && extra="--random-fully"
  for n in inet natA natB; do x $n sysctl -qw net.ipv4.ip_forward=1; done
  for n in natA natB; do
    x $n iptables -t nat -A POSTROUTING -o wan -j MASQUERADE $extra
    # A real home router's firewall: drop unsolicited inbound packets. (This also
    # matters for punching: a dropped packet leaves no conntrack entry behind
    # that would steal the port the inside host's mapping needs.)
    x $n iptables -A INPUT -i wan -m conntrack --ctstate NEW,INVALID -j DROP
    x $n iptables -A FORWARD -i wan -m conntrack --ctstate NEW,INVALID -j DROP
  done
  if [ "$1" = hotel ]; then x natA iptables -I FORWARD -i lan -p udp -j DROP; fi

  x inet "$W/stunserver" -listen 9.9.9.9:3478 >/dev/null 2>&1 & PIDS+=($!)
  x inet "$W/stunserver" -listen 9.9.9.10:3478 >/dev/null 2>&1 & PIDS+=($!)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=cp \
    -addext "subjectAltName=IP:9.9.9.20" -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
  local out; out=$("$EG" admin-token)
  TOKEN=$(grep -o 'vba_[A-Za-z0-9_-]*' <<<"$out")
  HASH=$(tail -1 <<<"$out" | tr -d ' ')
  (cd edge && ADMIN_TOKEN_SHA256=$HASH HOST=9.9.9.20 PORT=8787 TLS_CERT=$W/cert.pem TLS_KEY=$W/key.pem \
    exec ip netns exec eg-inet bun run src/dev.ts >"$W/server.log" 2>&1) & PIDS+=($!)
  sleep 1
}

export SSL_CERT_FILE="$W/cert.pem" XDG_CONFIG_HOME="$W/cfg"
SRV=https://9.9.9.20:8787
STUN=9.9.9.9:3478,9.9.9.10:3478

agent() { # ns, extra args...
  local n=$1; shift
  x "$n" env PATH="$PATH" SSL_CERT_FILE="$SSL_CERT_FILE" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    "$EG" up --server $SRV --name "$n" --iface "eg$n" --state-dir "$W/s-$n" --interval 5s --stun $STUN "$@" \
    >"$W/$n.log" 2>&1 &
  PIDS+=($!)
}

ipof() { x hub "$EG" devices ls | awk -v n="$1" '$2==n{print $3}'; }

wait_for() { # ns pattern seconds
  for _ in $(seq "$3"); do grep -q "$2" "$W/$1.log" && return 0; sleep 1; done
  echo "FAIL: $1 never logged '$2'"; tail -n +1 "$W"/*.log
  if [ -n "${DEBUG:-}" ]; then
    for n in natA natB; do echo "== conntrack $n"; x $n cat /proc/net/nf_conntrack 2>/dev/null | grep udp || x $n conntrack -L 2>/dev/null; done
    for n in lap phone; do echo "== $n"; x $n wg show "eg$n" 2>/dev/null || true; done
  fi
  exit 1
}

check() { # description, command...
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $d"; else echo "FAIL $d"; tail -n +1 "$W"/*.log; [ -n "${KEEP:-}" ] && sleep 300; exit 1; fi
}

status() { x "$1" env SSL_CERT_FILE="$SSL_CERT_FILE" "$EG" status --iface "eg$1" --state-dir "$W/s-$1"; }

status_has() { status "$1" | grep "$2" | grep -q "$3"; }

run() {
  local mode=$1
  echo "=== $mode NAT"
  setup "$mode"
  x hub "$EG" login --server $SRV --token "$TOKEN" >/dev/null
  agent hub --endpoint 203.0.113.10:51820 --hub
  sleep 2
  for n in lap phone; do VABBIT_SETUP_KEY=$(x hub "$EG" keys create 2>/dev/null) agent "$n"; done

  local want=direct
  [ "$mode" != cone ] && want=relay
  wait_for lap "peer phone: $want" 40
  wait_for phone "peer lap: $want" 40
  [ "$mode" != hotel ] && wait_for lap "peer hub: direct" 30
  wait_for phone "peer hub: direct" 30
  if [ "$mode" = symmetric ]; then check "symmetric NAT detected" grep -q "NAT: symmetric" "$W/lap.log"; fi
  if [ "$mode" = hotel ]; then
    wait_for lap "tunnelling over TCP" 30
    echo "ok   lap switched to TCP 443"
    check "status shows the TCP relay" status_has lap "To hub" "TCP relay"
  fi

  check "lap -> phone ($want)" x lap ping -c6 -W2 "$(ipof phone)"
  check "phone -> lap ($want)" x phone ping -c6 -W2 "$(ipof lap)"
  check "lap -> hub" x lap ping -c2 -W2 "$(ipof hub)"
  status lap

  if [ "$mode" = cone ]; then
    # Direct really bypasses the hub: lap's session to phone points at natB's public address.
    check "lap reaches phone at natB's public address" status_has lap phone '192.0.2.10:'
  else
    # Stays usable: lap still retries the punch in the background but relays meanwhile.
    check "lap relays to phone via hub" status_has lap phone 'relay via hub'
  fi

  # Removing a device tears it down.
  x hub "$EG" devices rm "$(x hub "$EG" devices ls | awk '$2=="phone"{print $1}')" >/dev/null
  wait_for phone "removed from the network" 20
  x phone ip link show egphone >/dev/null 2>&1 && { echo "FAIL removed device kept its interface"; exit 1; }
  echo "ok   removed device shut down"

  stop_all
  sleep 1
  for n in "${NS[@]}"; do ip netns del "eg-$n" 2>/dev/null || true; done
  rm -rf "$W/cfg" "$W"/s-* "$W"/*.log
}

modes=("$@")
[ ${#modes[@]} -eq 0 ] && modes=(cone symmetric hotel)
for m in "${modes[@]}"; do run "$m"; done
echo PASS
