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

# E2E test entrypoint for xKey GUI application.
# Starts swtpm, Xvfb, and wails dev server, then runs Playwright tests.

set -euo pipefail

WAILS_PORT="${WAILS_PORT:-34115}"
BASE_URL="${BASE_URL:-http://localhost:${WAILS_PORT}}"
SWTPM_STATE="/tmp/swtpm"
SWTPM_PORT=2321
SWTPM_CTRL_PORT=2322
MAX_WAIT_SECONDS=120
CLEANUP_PIDS=()

# ---------------------------------------------------------------------------
# Cleanup handler: terminate background processes on exit
# ---------------------------------------------------------------------------
cleanup() {
    echo "[entrypoint] Cleaning up background processes..."
    for pid in "${CLEANUP_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    echo "[entrypoint] Cleanup complete."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Start swtpm (software TPM 2.0 simulator)
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting swtpm on port ${SWTPM_PORT}..."
mkdir -p "${SWTPM_STATE}"
swtpm socket \
    --tpmstate dir="${SWTPM_STATE}" \
    --tpm2 \
    --server type=tcp,port="${SWTPM_PORT}" \
    --ctrl type=tcp,port="${SWTPM_CTRL_PORT}" \
    --flags not-need-init &
SWTPM_PID=$!
CLEANUP_PIDS+=("$SWTPM_PID")
sleep 1

if ! kill -0 "$SWTPM_PID" 2>/dev/null; then
    echo "[entrypoint] ERROR: swtpm failed to start"
    exit 1
fi
echo "[entrypoint] swtpm running (PID ${SWTPM_PID})"

# ---------------------------------------------------------------------------
# 2. Start Xvfb virtual display
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting Xvfb on display :99..."
Xvfb :99 -screen 0 1920x1080x24 &
XVFB_PID=$!
CLEANUP_PIDS+=("$XVFB_PID")
sleep 1

if ! kill -0 "$XVFB_PID" 2>/dev/null; then
    echo "[entrypoint] ERROR: Xvfb failed to start"
    exit 1
fi
echo "[entrypoint] Xvfb running (PID ${XVFB_PID})"
export DISPLAY=:99

# ---------------------------------------------------------------------------
# 2.5. Initialize SoftHSM PIV test certificates
# ---------------------------------------------------------------------------
SOFTHSM_PIV_SETUP="/workspace/xkey/test/e2e/setup-softhsm-piv.sh"
if [ -x "$SOFTHSM_PIV_SETUP" ]; then
    echo "[entrypoint] Setting up SoftHSM PIV test certificates..."
    bash "$SOFTHSM_PIV_SETUP"
    echo "[entrypoint] SoftHSM PIV setup complete."
else
    echo "[entrypoint] SoftHSM PIV setup script not found, skipping."
fi

# ---------------------------------------------------------------------------
# 3. Install frontend npm dependencies
# ---------------------------------------------------------------------------
echo "[entrypoint] Installing frontend npm dependencies..."
cd /workspace/xkey/frontend
npm ci
echo "[entrypoint] Frontend dependencies installed."

# ---------------------------------------------------------------------------
# 4. Install Playwright browsers (ensures correct version match)
# ---------------------------------------------------------------------------
echo "[entrypoint] Installing Playwright Chromium..."
npx playwright install chromium
echo "[entrypoint] Playwright Chromium installed."

# ---------------------------------------------------------------------------
# 5. Download Go module dependencies
# ---------------------------------------------------------------------------
echo "[entrypoint] Downloading Go module dependencies..."
export GONOSUMCHECK='*'
export GONOSUMDB='*'
export GOFLAGS='-buildvcs=false'
# The upstream google/go-sev-guest v0.14.0 module was re-tagged, causing
# checksum mismatches between local builds and Docker builds. Remove the
# conflicting entries so go mod download accepts the proxy's archive.
# Use temp copies to avoid modifying the host's go.sum via bind mount.
for f in /workspace/go.sum /workspace/xkey/go.sum /workspace/sdk/go/go.sum; do
  if [ -f "$f" ]; then
    grep -v 'google/go-sev-guest' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
  fi
done
cd /workspace/xkey
go mod download
cd /workspace
go mod download
cd /workspace/sdk/go
go mod download
cd /workspace/xkey
echo "[entrypoint] Go modules downloaded."

# ---------------------------------------------------------------------------
# 6. Start wails dev server in background
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting wails dev server..."
GONOSUMCHECK='*' GONOSUMDB='*' wails dev -tags "ble,production,webkit2_41" &
WAILS_PID=$!
CLEANUP_PIDS+=("$WAILS_PID")

# ---------------------------------------------------------------------------
# 7. Wait for wails dev server to be ready
# ---------------------------------------------------------------------------
echo "[entrypoint] Waiting for wails dev server at ${BASE_URL}..."
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_SECONDS" ]; do
    if curl -s -o /dev/null -w '' "${BASE_URL}" 2>/dev/null; then
        echo "[entrypoint] Wails dev server is ready (${elapsed}s elapsed)."
        break
    fi
    if ! kill -0 "$WAILS_PID" 2>/dev/null; then
        echo "[entrypoint] ERROR: wails dev process exited unexpectedly"
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ "$elapsed" -ge "$MAX_WAIT_SECONDS" ]; then
    echo "[entrypoint] ERROR: wails dev server failed to start within ${MAX_WAIT_SECONDS}s"
    exit 1
fi

# ---------------------------------------------------------------------------
# 8. Run Playwright E2E tests
# ---------------------------------------------------------------------------
echo "[entrypoint] Running Playwright E2E tests..."
cd /workspace/xkey/frontend
TEST_EXIT=0
npx playwright test || TEST_EXIT=$?

# ---------------------------------------------------------------------------
# 9. Report results
# ---------------------------------------------------------------------------
if [ "$TEST_EXIT" -eq 0 ]; then
    echo "[entrypoint] All E2E tests passed."
else
    echo "[entrypoint] E2E tests failed with exit code ${TEST_EXIT}."
fi

exit "$TEST_EXIT"
