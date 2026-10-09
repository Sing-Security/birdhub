#!/bin/sh
# ==============================================================================
# birdhub — enrollment for the compose demo
# ==============================================================================
#
# One fleet, two members, four files. This is the whole CA flow that a real
# deployment splits across machines (the CA key belongs on the CA machine and
# nowhere else); the demo collapses it because everything shares one volume.
#
# Idempotent: if the CA key already exists the fleet is presumed enrolled and
# nothing is regenerated. Regenerating the CA would invalidate both
# certificates, and regenerating an identity would change who a node is.

set -eu

KEYS=/etc/birdhub/keys

if [ -f "$KEYS/ca.key" ]; then
    echo "enroll: fleet already enrolled ($KEYS/ca.key exists)"
    exit 0
fi

echo "enroll: creating fleet CA"
birdhub ca init --key "$KEYS/ca.key" --pub "$KEYS/ca.pub" --id demo-ca

echo "enroll: generating member identities"
birdhub identity export --key "$KEYS/hub.key"    --pub "$KEYS/hub.pub"    --name hub.example
birdhub identity export --key "$KEYS/client.key" --pub "$KEYS/client.pub" --name laptop.example

echo "enroll: issuing certificates"
birdhub ca issue --ca "$KEYS/ca.key" --identity "$KEYS/hub.pub"    --days 365 --out "$KEYS/hub.cert"
birdhub ca issue --ca "$KEYS/ca.key" --identity "$KEYS/client.pub" --days 365 --out "$KEYS/client.cert"

echo "enroll: done — hub.example and laptop.example certified by demo-ca"
