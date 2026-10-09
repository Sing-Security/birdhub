#!/bin/sh
# ==============================================================================
# birdhub — a native node joins the compose fleet
# ==============================================================================
#
# The compose file runs hub + laptop + origin as containers. This script adds
# one more member to that same fleet: a node running as a plain process on
# this machine, from the release binary. Nothing about the node changes for
# being outside a container — same binary, same certificates, same config
# shape — only the hub's address is the published port instead of a compose
# service name:
#
#   curl → desktop (this machine) → hub (container) → laptop (container) → origin (container)
#
# `desktop` asks the hub to pair it with `laptop.example`; the two run their
# own end-to-end session inside that pairing; `laptop`'s `web` service dials
# `origin:80`, which resolves only inside the compose network. The hub copies
# ciphertext between a process it cannot route to and a container neither
# side can address.
#
# Run from anywhere; the script finds the repository. It leaves the node
# connected and waits — Ctrl-C stops the node, the containers keep running.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE=${STATE:-/tmp/birdhub-fleet}
BIN=${BIN:-$ROOT/target/release/birdhub}

if [ ! -x "$BIN" ]; then
    echo "fleet: building the release binary (once)"
    (cd "$ROOT" && cargo build --release --locked)
fi

echo "fleet: bringing up the compose fleet"
(cd "$ROOT" && docker compose up --build -d >/dev/null)

# The client prints its own 'session' line before the hub has finished
# verifying it, so wait on the hub's view: the node is reachable for pairing
# exactly when the hub says so.
printf "fleet: waiting for the hub to register laptop.example"
i=0
while ! (cd "$ROOT" && docker compose logs hub 2>/dev/null | grep -q "with 'laptop.example'"); do
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        printf "\nfleet: hub never registered laptop.example — check: docker compose logs hub\n" >&2
        exit 1
    fi
    printf .
    sleep 0.5
done
printf "\n"

mkdir -p "$STATE/keys"
# The CA key belongs on the CA machine and nowhere else; in this demo the CA
# "machine" is the compose volume, and reaching into it is how the native
# node gets certified. A real fleet would carry over only the certificate.
echo "fleet: copying the fleet's CA material out of the volume"
for f in ca.key ca.pub hub.cert; do
    (cd "$ROOT" && docker compose cp "hub:/etc/birdhub/keys/$f" "$STATE/keys/$f" >/dev/null)
done

echo "fleet: enrolling desktop.example with the fleet CA"
"$BIN" identity export --key "$STATE/keys/desktop.key" --pub "$STATE/keys/desktop.pub" --name desktop.example
"$BIN" ca issue --ca "$STATE/keys/ca.key" --identity "$STATE/keys/desktop.pub" --days 365 --out "$STATE/keys/desktop.cert"

cat >"$STATE/desktop.toml" <<EOF
[app]
mode = "client"

[identity]
key_file = "$STATE/keys/desktop.key"
name = "desktop.example"
certificate = "$STATE/keys/desktop.cert"

[ca]
public = "$STATE/keys/ca.pub"

[peer]
# The published port, not a compose service name: the hub is reached from
# this process the same way it is reached from any other fleet member.
address = "127.0.0.1:8388"
hub_cert = "$STATE/keys/hub.cert"

[[transports]]
name = "webpeer"
local_address = "127.0.0.1:1090"
forward_to = "laptop.example/web"
EOF

echo "fleet: starting desktop.example"
"$BIN" "$STATE/desktop.toml" >"$STATE/desktop.log" 2>&1 &
NODE=$!
trap 'kill "$NODE" 2>/dev/null; wait "$NODE" 2>/dev/null' EXIT INT TERM

i=0
while ! grep -q "Node: session" "$STATE/desktop.log" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        printf "fleet: desktop never established a session:\n" >&2
        cat "$STATE/desktop.log" >&2
        exit 1
    fi
    sleep 0.5
done

# The hub registers a peer only once its handshake finishes verifying (the
# post-quantum verify is the long part); a request inside that window is told
# 'not connected' although the node's own log already says it is up. One
# handshake's worth of time, then the request is answered.
sleep 3

echo
echo "=== curl -s http://127.0.0.1:1090/   (desktop → hub → laptop's 'web' → origin)"
curl -s -m 20 http://127.0.0.1:1090/ || true

echo
echo "=== hub and laptop (containers)"
(cd "$ROOT" && docker compose logs hub client 2>/dev/null \
    | grep -e "pairing" -e "serving" -e "session .* with 'desktop.example'" || true)
echo "=== desktop (this machine)"
grep -e "peer session" -e "serving" "$STATE/desktop.log" || true

echo
echo "desktop.example is still connected (log: $STATE/desktop.log)."
echo "Ctrl-C stops it; 'docker compose down' stops the containers."
wait "$NODE"
