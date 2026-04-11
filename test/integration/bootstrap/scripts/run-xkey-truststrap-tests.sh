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
cat >/tmp/go.work <<'EOF'
go 1.26.1

use (
    /workspace
    /workspace/sdk/go
    /workspace/xkey
    /go-qrdb
    /go-qrdb/sdk/go
    /go-quicraft
)

// Explicit replace directives for the v0.0.0 requires that the
// workspace alone cannot satisfy (indirect transitive requires on
// unpublished revisions). Each replacement points at the same
// directory the matching `use` directive imports.
replace github.com/jeremyhahn/go-quicraft v0.0.0 => /go-quicraft
replace github.com/jeremyhahn/go-qrdb v0.0.0 => /go-qrdb
replace github.com/jeremyhahn/go-qrdb/sdk/go v0.0.0 => /go-qrdb/sdk/go
replace github.com/jeremyhahn/go-xkms v0.0.0 => /workspace
replace github.com/jeremyhahn/go-xkms/sdk/go v0.0.0 => /workspace/sdk/go
replace github.com/jeremyhahn/go-xkms/xkey v0.0.0 => /workspace/xkey
EOF
export GOWORK=/tmp/go.work

echo 'Running xkey TrustService truststrap integration tests...'
cd /workspace/xkey
exec go test -v -tags=integration ./test/integration/truststrap/... -timeout 5m
