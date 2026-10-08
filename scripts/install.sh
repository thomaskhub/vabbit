#!/bin/sh
# Install the Vabbit client on Linux or macOS, and optionally join a network.
#
#   curl -fsSL https://raw.githubusercontent.com/thomaskhub/vabbit/main/scripts/install.sh | sudo sh
#
# Join a network in the same step (the setup key comes from `vabbit keys create`):
#
#   curl -fsSL https://raw.githubusercontent.com/thomaskhub/vabbit/main/scripts/install.sh |
#     sudo VABBIT_SERVER=https://mynet.b-cdn.net VABBIT_SETUP_KEY=vbk_... sh
#
# Settings (environment variables):
#   VABBIT_VERSION     release tag to install, e.g. v0.1.0 (default: latest)
#   VABBIT_SERVER      control plane URL; with VABBIT_SETUP_KEY, enroll and start the service
#   VABBIT_SETUP_KEY   one-time setup key
#   VABBIT_NAME        device name (default: hostname)
#   VABBIT_ENDPOINT    public HOST:PORT, for machines with a public IP (e.g. a hub)
#   VABBIT_IFACE       WireGuard interface (default: vb0)
#   GITHUB_TOKEN       needed while the repository is private
#   VABBIT_REPO        GitHub repository (default: thomaskhub/vabbit)
#
# Every download is checked against the release's SHA256SUMS before anything is installed.
set -eu

REPO=${VABBIT_REPO:-thomaskhub/vabbit}
VERSION=${VABBIT_VERSION:-latest}
IFACE=${VABBIT_IFACE:-vb0}
BIN_DIR=/usr/local/bin
UNIT_DIR=/etc/systemd/system

say() { printf 'vabbit: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "the Vabbit client runs on Linux, macOS and Windows (install.ps1)" ;;
esac
[ "$(id -u)" = 0 ] || die "run as root (pipe into: sudo sh)"
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported CPU $(uname -m); amd64 and arm64 are available" ;;
esac
command -v curl >/dev/null 2>&1 || die "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  SHA256SUM=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  SHA256SUM="shasum -a 256" # macOS
else
  die "sha256sum is required (coreutils)"
fi
if [ "$OS" = linux ]; then
  command -v ip >/dev/null 2>&1 || say "warning: 'ip' (iproute2) is missing; install it before running vabbit up"
  [ -c /dev/net/tun ] || say "warning: /dev/net/tun is missing; containers need it passed through"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

# fetch NAME: download one release asset into $TMP.
fetch() {
  if [ -n "${VABBIT_BASE_URL:-}" ]; then # a mirror, or a local directory for testing
    curl -fsSL -o "$TMP/$1" "$VABBIT_BASE_URL/$1" && return
    die "could not download $1 from $VABBIT_BASE_URL"
  fi
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    # Private repository: find the asset through the API, then download it.
    if [ ! -f "$TMP/release.json" ]; then
      if [ "$VERSION" = latest ]; then rel=latest; else rel="tags/$VERSION"; fi
      curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
        -o "$TMP/release.json" "https://api.github.com/repos/$REPO/releases/$rel" ||
        die "release $VERSION not found in $REPO (check GITHUB_TOKEN and VABBIT_VERSION)"
    fi
    # One JSON key per line; an asset's API "url" comes just before its "name".
    url=$(tr ',{}' '[\n*]' <"$TMP/release.json" | awk -v n="\"$1\"" '
      /"url": *"https:\/\/api\.github\.com\/repos\/.*\/releases\/assets\/[0-9]+"/ { u = $0 }
      $0 ~ "\"name\": *" n "$" { print u; exit }' | sed 's/.*"\(https[^"]*\)".*/\1/')
    [ -n "$url" ] || die "release $VERSION has no asset $1"
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/octet-stream" -o "$TMP/$1" "$url" ||
      die "could not download $1"
    return
  fi
  if [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi
  curl -fsSL -o "$TMP/$1" "$base/$1" ||
    die "could not download $1 (a private repository needs GITHUB_TOKEN)"
}

BIN=vabbit-$OS-$ARCH
if [ "$OS" = linux ]; then FILES="$BIN vabbit@.service"; else FILES=$BIN; fi
say "downloading $BIN ($VERSION) from $REPO"
fetch SHA256SUMS
for f in $FILES; do
  fetch "$f"
  line=$(grep -E "^[0-9a-f]{64} [ *]?$(printf '%s' "$f" | sed 's/[.@]/\\&/g')\$" "$TMP/SHA256SUMS" | head -n 1)
  [ -n "$line" ] || die "SHA256SUMS does not list $f"
  (cd "$TMP" && printf '%s\n' "$line" | $SHA256SUM -c - >/dev/null) || die "checksum mismatch for $f, nothing installed"
done

# A running macOS service holds the old binary: stop it during the upgrade.
PLIST=/Library/LaunchDaemons/com.vabbit.$IFACE.plist
if [ "$OS" = darwin ] && [ -f "$PLIST" ]; then
  launchctl bootout "system/com.vabbit.$IFACE" 2>/dev/null || true
  RESTART=1
fi
mkdir -p "$BIN_DIR"
install -m 0755 "$TMP/$BIN" "$BIN_DIR/vabbit"
say "installed $BIN_DIR/vabbit ($("$BIN_DIR/vabbit" version))"
if [ "$OS" = linux ] && [ -d /run/systemd/system ]; then
  install -m 0644 "$TMP/vabbit@.service" "$UNIT_DIR/vabbit@.service"
  systemctl daemon-reload
  say "installed the vabbit@.service unit"
fi

if [ -n "${VABBIT_SETUP_KEY:-}" ] && [ -n "${VABBIT_SERVER:-}" ]; then
  set -- up --server "$VABBIT_SERVER" --iface "$IFACE" --dry-run
  [ -n "${VABBIT_NAME:-}" ] && set -- "$@" --name "$VABBIT_NAME"
  [ -n "${VABBIT_ENDPOINT:-}" ] && set -- "$@" --endpoint "$VABBIT_ENDPOINT"
  say "joining $VABBIT_SERVER"
  VABBIT_SETUP_KEY=$VABBIT_SETUP_KEY "$BIN_DIR/vabbit" "$@" >/dev/null || die "enrolling failed"
  if [ "$OS" = darwin ]; then
    "$BIN_DIR/vabbit" service install --iface "$IFACE" >/dev/null || die "could not start the service"
    say "joined; the tunnel runs as the launchd service com.vabbit.$IFACE. Check it with: sudo vabbit status"
  elif [ -d /run/systemd/system ]; then
    systemctl enable --now "vabbit@$IFACE" >/dev/null 2>&1 || die "could not start vabbit@$IFACE"
    say "joined; the tunnel runs as vabbit@$IFACE. Check it with: sudo vabbit status"
  else
    say "joined; no systemd here, start the tunnel with: sudo vabbit up --iface $IFACE"
  fi
elif [ -n "${RESTART:-}" ]; then
  launchctl bootstrap system "$PLIST" || die "could not restart com.vabbit.$IFACE"
  say "restarted com.vabbit.$IFACE"
else
  say "done. Join a network with:"
  say "  sudo VABBIT_SETUP_KEY=vbk_... vabbit up --server https://mynet.b-cdn.net --dry-run"
  if [ "$OS" = darwin ]; then
    say "  sudo vabbit service install"
  else
    say "  sudo systemctl enable --now vabbit@vb0"
  fi
fi
