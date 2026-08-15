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

BOOTSTRAP_NOISE_STATIC_KEY="$(cat /etc/xkms/certs/noise.pub.hex)"
BOOTSTRAP_SPKI_PIN="$(cat /etc/xkms/certs/spki.pin)"
export BOOTSTRAP_NOISE_STATIC_KEY BOOTSTRAP_SPKI_PIN
echo "Noise public key: ${BOOTSTRAP_NOISE_STATIC_KEY}"
echo "SPKI pin: ${BOOTSTRAP_SPKI_PIN}"

echo 'Running xkey TrustService truststrap integration tests...'
cd /workspace/xkey
exec go test -v -tags=integration ./test/integration/truststrap/... -timeout 5m
