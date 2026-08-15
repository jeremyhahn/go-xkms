#!/usr/bin/env bash
# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-xkms.
#
# go-xkms is dual-licensed:
#
# 1. GNU Affero General Public License v3.0 (AGPL-3.0)
#    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
#
# 2. Commercial License
#    Contact licensing@automatethethings.com for commercial licensing options.

# FIDO2 backend-binding integration test entrypoint.
# Starts swtpm + SoftHSM2, then runs the Go keybackend integration tests
# with the "swtpm" and "pkcs11" build tags against real hardware simulators.

set -euo pipefail

SWTPM_STATE="/tmp/swtpm"
CLEANUP_PIDS=()

cleanup() {
    echo "[fido2-hardware] Cleaning up..."
    for pid in "${CLEANUP_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [ -f /tmp/xkey-go.mod.orig ]; then
        cp /tmp/xkey-go.mod.orig /workspace/xkey/go.mod 2>/dev/null || true
    fi
    echo "[fido2-hardware] Cleanup complete."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Start an ephemeral swtpm (software TPM 2.0) on a unix socket.
# ---------------------------------------------------------------------------
# Fresh TPM state on every run (no persistence, nothing to clear), provisioned
# with an EK + platform certificate so it looks like real hardware. Exposed as a
# unix-socket "device" that the keybackend test opens via TPM_DEVICE exactly
# like a real TPM (xkms serves a ".sock" device through linuxudstpm). The
# in-process google simulator is unit-tests-only.
SWTPM_SOCK="${SWTPM_STATE}/swtpm.sock"
echo "[fido2-hardware] Starting ephemeral swtpm on ${SWTPM_SOCK}..."
rm -rf "${SWTPM_STATE}"
mkdir -p "${SWTPM_STATE}"
swtpm_setup --tpm2 --tpmstate "${SWTPM_STATE}" --overwrite --pcr-banks sha256 \
    --create-ek-cert --create-platform-cert
swtpm socket \
    --tpm2 \
    --tpmstate dir="${SWTPM_STATE}" \
    --server type=unixio,path="${SWTPM_SOCK}" \
    --ctrl type=unixio,path="${SWTPM_SOCK}.ctrl" \
    --flags startup-clear,not-need-init \
    --log level=1,file="${SWTPM_STATE}/swtpm.log" &
SWTPM_PID=$!
CLEANUP_PIDS+=("$SWTPM_PID")

# Wait for the swtpm command socket to be ready before any client connects.
for _ in $(seq 1 30); do
    [ -S "${SWTPM_SOCK}" ] && break
    sleep 0.2
done
if [ ! -S "${SWTPM_SOCK}" ] || ! kill -0 "$SWTPM_PID" 2>/dev/null; then
    echo "[fido2-hardware] ERROR: swtpm failed to start"
    cat "${SWTPM_STATE}/swtpm.log" 2>/dev/null || true
    exit 1
fi
export TPM_DEVICE="${SWTPM_SOCK}"
echo "[fido2-hardware] swtpm running (PID ${SWTPM_PID}, socket ${SWTPM_SOCK})"

# ---------------------------------------------------------------------------
# 2. Initialize SoftHSM2 PIV test token
# ---------------------------------------------------------------------------
echo "[fido2-hardware] Initializing SoftHSM2 PIV test token..."
SETUP_SCRIPT="/workspace/xkey/test/e2e/setup-softhsm-piv.sh"
if [ -x "${SETUP_SCRIPT}" ]; then
    bash "${SETUP_SCRIPT}"
    echo "[fido2-hardware] SoftHSM PIV setup complete."
else
    # Fallback: initialize a minimal token so the pkcs11 backend can connect.
    softhsm2-util --init-token --free \
        --label "e2e-piv-test" \
        --so-pin 12345678 \
        --pin 123456
    echo "[fido2-hardware] Initialized minimal SoftHSM2 token (setup script absent)."
fi

# ---------------------------------------------------------------------------
# 3. Set up Go workspace (mirrors e2e/entrypoint.sh)
# ---------------------------------------------------------------------------
echo "[fido2-hardware] Configuring Go workspace..."
export GONOSUMCHECK='*'
export GONOSUMDB='*'
export GOFLAGS='-buildvcs=false'
export CGO_ENABLED=1

# Remove any stale go-sev-guest checksum entries that cause proxy mismatches.
for f in /workspace/go.sum /workspace/xkey/go.sum /workspace/sdk/go/go.sum; do
    if [ -f "$f" ]; then
        grep -v 'google/go-sev-guest' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
    fi
done

# Inject local-path replaces into xkey/go.mod so the test binary resolves
# in-house transitive dependencies without network access.
cp /workspace/xkey/go.mod /tmp/xkey-go.mod.orig
for repl in \
    "github.com/jeremyhahn/go-qrdb=../../go-qrdb" \
    "github.com/jeremyhahn/go-qrdb/sdk/go=../../go-qrdb/sdk/go" \
    "github.com/jeremyhahn/go-truststrap=../../go-truststrap" \
    "github.com/jeremyhahn/go-codec=../../go-codec" \
    "github.com/jeremyhahn/go-frost=../../go-frost" \
    "github.com/jeremyhahn/go-objstore=../../go-objstore" \
    "github.com/jeremyhahn/go-quicraft=../../go-quicraft"; do
    (cd /workspace/xkey && go mod edit -replace "$repl")
done
echo "[fido2-hardware] Injected in-house module replaces."

cd /workspace/xkey
go mod download all
echo "[fido2-hardware] Go modules downloaded."

# ---------------------------------------------------------------------------
# 4. Determine SoftHSM library path
# ---------------------------------------------------------------------------
PKCS11_LIB="${PKCS11_LIBRARY:-}"
if [ -z "${PKCS11_LIB}" ]; then
    for candidate in \
        "/usr/lib/softhsm/libsofthsm2.so" \
        "/usr/local/lib/softhsm/libsofthsm2.so" \
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"; do
        if [ -f "${candidate}" ]; then
            PKCS11_LIB="${candidate}"
            break
        fi
    done
fi
if [ -z "${PKCS11_LIB}" ]; then
    echo "[fido2-hardware] WARNING: SoftHSM2 library not found; pkcs11 tests will skip"
fi
export PKCS11_LIBRARY="${PKCS11_LIB}"

# ---------------------------------------------------------------------------
# 5. Run FIDO2 backend adapter integration tests
# ---------------------------------------------------------------------------
# TPM_DEVICE points the tpm2 backend test at the swtpm unix-socket device.

echo "[fido2-hardware] Running FIDO2 backend adapter integration tests..."
echo "[fido2-hardware]   TPM_DEVICE=${TPM_DEVICE}"
echo "[fido2-hardware]   PKCS11_LIBRARY=${PKCS11_LIBRARY}"

go test \
    -v \
    -count=1 \
    -timeout=20m \
    -tags "integration swtpm pkcs11 production codec_json ble" \
    ./pkg/authenticator/keybackend/...

TEST_EXIT=$?

if [ "${TEST_EXIT}" -eq 0 ]; then
    echo "[fido2-hardware] All FIDO2 backend adapter tests passed."
else
    echo "[fido2-hardware] Tests failed with exit code ${TEST_EXIT}."
fi

exit "${TEST_EXIT}"
