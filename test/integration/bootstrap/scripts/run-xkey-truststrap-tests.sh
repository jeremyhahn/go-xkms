#!/bin/sh
# Copyright (c) 2026 Jeremy Hahn
# Copyright (c) 2026 Automate The Things, LLC
#
# Runs the xkey TrustService truststrap integration tests inside the
# bootstrap docker-compose stack. Builds a transient go.work at
# /tmp/go.work that stitches together the root go-xkms module, the
# xkey submodule, sdk/go, and the sibling-mounted go-qrdb / go-quicraft
# modules so cross-module v0.0.0 requires resolve cleanly without
# touching any bind-mounted file on the host.
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

echo 'Building transient go.work for cross-module resolution...'
# Delegate to the single canonical generator so the module set + version-specific
# replaces never drift from the other container contexts. All siblings are mounted
# at /go-<name> by this stack's docker-compose.yml; repo root is /workspace.
bash /workspace/scripts/gen-gowork.sh /workspace /tmp/go.work
export GOWORK=/tmp/go.work

echo 'Running xkey TrustService truststrap integration tests...'
cd /workspace/xkey
exec go test -v -tags=integration ./test/integration/truststrap/... -timeout 5m
