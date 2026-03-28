#!/bin/bash

# ==============================================================================
# Mock System Binaries
# ==============================================================================
# This script serves as a multi-call binary to mock systemctl, nft, ip, and netbird
# allowing the birdhub agent to run in lightweight Docker containers without
# requiring a full systemd init system or causing fatal errors on missing tables.

COMMAND=$(basename "$0")

case "$COMMAND" in
  # --- Mock NetBird Identity ---
  netbird)
    if [[ "$1" == "status" && "$2" == "--json" ]]; then
        IP="${NETBIRD_IP:-100.64.0.10}"
        PUBKEY="${NETBIRD_PUBKEY:-$(echo "mock-key-$HOSTNAME" | sha256sum | cut -c1-44)}"
        FQDN="${NETBIRD_HOSTNAME:-$HOSTNAME.netbird.cloud}"

        cat <<EOF
{
  "localPeerState": {
    "localIP": "$IP",
    "publicKey": "$PUBKEY",
    "hostname": "$FQDN"
  },
  "managementState": {
    "connected": true
  }
}
EOF
        exit 0
    fi
    ;;

  # --- Mock Systemd (systemctl) ---
  systemctl)
    # Always succeed for reload/restart of services (like unbound)
    # We don't actually have a service manager in the container.
    echo "Mock systemctl: $@" >&2
    exit 0
    ;;

  # --- Mock nftables ---
  nft)
    # nftables requires kernel modules usually missing in basic containers.
    # We log the rules being applied but always return success.
    echo "Mock nft: $@" >&2
    exit 0
    ;;

  # --- Mock iproute2 (ip) ---
  ip)
    # The agent calls 'ip route flush table X'. This can fail in containers
    # if the table doesn't exist. We log the call and exit successfully
    # to prevent the agent from crashing.
    echo "Mock ip: $@" >&2
    exit 0
    ;;

  *)
    echo "Error: Mock command '$COMMAND' not recognized." >&2
    exit 1
    ;;
esac
