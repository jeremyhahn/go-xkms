#!/bin/sh
# Copyright (c) 2026 Jeremy Hahn
# Copyright (c) 2026 Automate The Things, LLC
#
# Runs the xkey TrustService truststrap integration tests inside the
# bootstrap docker-compose stack. The root go-xkms module, the xkey
# submodule, sdk/go, and the go-qrdb / go-quicraft in-house modules all
# resolve from their tagged Gitea releases via the container's git
# config redirect (see dependency-resolution.md), so no local workspace
# or bind-mounted sibling checkout is required.
set -eu

echo 'Adding test CA to system trust store...'
cp /etc/xkms/certs/ca.crt /usr/local/share/ca-certificates/xkms-test-ca.crt
update-ca-certificates >/dev/null 2>&1

echo 'Waiting for CoreDNS to initialize...'
sleep 5

# The Noise listener generates or unseals its own key (go-xkms#35); there is
# no file to read it from. Discover the running server's actual key over its
# admin API (go-xkms#632) instead of a pre-shared value generate-test-certs.sh
# can no longer produce.
echo 'Discovering the running server bootstrap keys...'
BOOTSTRAP_KEYS_JSON="$(cd /workspace && go run ./cmd/xkmsctl bootstrap show-keys --output json \
    --transport rest --server https://xkms-server:8443 --tls-ca /etc/xkms/certs/ca.crt)"
BOOTSTRAP_NOISE_STATIC_KEY="$(printf '%s' "${BOOTSTRAP_KEYS_JSON}" | sed -n 's/.*"noise_public_key":"\([^"]*\)".*/\1/p')"
BOOTSTRAP_SPKI_PIN="$(cat /etc/xkms/certs/spki.pin)"
export BOOTSTRAP_NOISE_STATIC_KEY BOOTSTRAP_SPKI_PIN
echo "Noise public key: ${BOOTSTRAP_NOISE_STATIC_KEY}"
echo "SPKI pin: ${BOOTSTRAP_SPKI_PIN}"

if [ -z "${BOOTSTRAP_NOISE_STATIC_KEY}" ]; then
    echo "ERROR: failed to discover the server's Noise public key via 'bootstrap show-keys'"
    echo "Response was: ${BOOTSTRAP_KEYS_JSON}"
    exit 1
fi

echo 'Running xkey TrustService truststrap integration tests...'
cd /workspace/xkey
exec go test -v -tags=integration ./test/integration/truststrap/... -timeout 5m
