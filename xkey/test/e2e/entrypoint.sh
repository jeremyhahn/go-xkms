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
# wails dev compiles the full GUI Go app on first boot; from a cold build cache
# (e.g. right after `docker compose build`) this can exceed 6 minutes, so allow
# generous headroom to avoid a false "failed to start" on a slow compile.
MAX_WAIT_SECONDS=900
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
    # Restore the committed xkey/go.mod if we injected local-path replaces
    # (the file is bind-mounted from the host, so leave it as committed).
    if [ -f /tmp/xkey-go.mod.orig ]; then
        cp /tmp/xkey-go.mod.orig /workspace/xkey/go.mod 2>/dev/null || true
    fi
    echo "[entrypoint] Cleanup complete."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Start an ephemeral swtpm (software TPM 2.0) on a unix socket.
# ---------------------------------------------------------------------------
# Mirrors go-trusted-platform's devcontainer start_swtpm: a fresh TPM state on
# every container start (no persistence, nothing to clear) exposed as a
# unix-socket "device". The xkey/xkms binaries open this socket exactly like a
# real hardware TPM (config: device=<sock>, simulator=false). The in-process
# google simulator (UseSimulator) is unit-tests-only and never linked here.
SWTPM_SOCK="${SWTPM_STATE}/swtpm.sock"
echo "[entrypoint] Starting ephemeral swtpm on ${SWTPM_SOCK}..."
rm -rf "${SWTPM_STATE}"
mkdir -p "${SWTPM_STATE}"
# --create-ek-cert / --create-platform-cert provision the TPM with an EK
# certificate (and platform cert) at the standard NV indices, exactly like a
# real TPM ships from the manufacturer. xkms reads the RSA EK cert from
# 0x01C00002 (DefaultTPMConfig.EK.CertHandle) during provisioning so the EK is
# verifiable instead of "EK certificate not available".
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
    echo "[entrypoint] ERROR: swtpm failed to start"
    cat "${SWTPM_STATE}/swtpm.log" 2>/dev/null || true
    exit 1
fi
echo "[entrypoint] swtpm running (PID ${SWTPM_PID}, socket ${SWTPM_SOCK})"

# ---------------------------------------------------------------------------
# 1.5. Write xkey unified config pointing the TPM at the swtpm socket device.
# ---------------------------------------------------------------------------
# AutoInitialize reads ~/.config/xkey/xkey.yaml via config.Load(). Both the
# global/platform TPM (top-level `tpm:`) and the tpm2 backend point at the
# swtpm unix socket as their device with simulator=false, so xkms opens it via
# linuxudstpm and provisions a fresh TPM. The FIDO2 service then registers a
# real "tpm2" backend so Playwright tests A-1..A-5 can verify it.
XKEY_CFG_DIR="${HOME}/.config/xkey"
mkdir -p "${XKEY_CFG_DIR}"
cat > "${XKEY_CFG_DIR}/xkey.yaml" <<XKEYCFG
tpm:
  device: ${SWTPM_SOCK}
  simulator: false
backends:
  local:
    - id: tpm2-swtpm
      category: tpm2
      name: "TPM 2.0 (swtpm)"
      tpm2:
        device: ${SWTPM_SOCK}
        simulator: false
XKEYCFG
echo "[entrypoint] Wrote xkey config for swtpm at ${XKEY_CFG_DIR}/xkey.yaml"

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

# Generate a Go workspace covering the in-house module closure so that not only
# `go build` but also the wails binding generator (golang.org/x/tools/go/packages)
# resolves the nested in-house modules with full type information. Without this,
# wails dev fails with: internal error: package "github.com/jeremyhahn/go-qrdb/sdk/go"
# without types was imported from ".../xkey/pkg/pcr_policy". The siblings are
# bind-mounted at /go-<name> by docker-compose.yml.
# Generate the container Go workspace via the single canonical generator
# (scripts/gen-gowork.sh) so the replace set never drifts from the other
# container contexts. Siblings are bind-mounted at /go-<name>; repo root is
# /workspace.
bash /workspace/scripts/gen-gowork.sh /workspace /tmp/go.work
export GOWORK=/tmp/go.work

# The upstream google/go-sev-guest v0.14.0 module was re-tagged, causing
# checksum mismatches between local builds and Docker builds. Remove the
# conflicting entries so go mod download accepts the proxy's archive.
for f in /workspace/go.sum /workspace/xkey/go.sum /workspace/sdk/go/go.sum; do
  if [ -f "$f" ]; then
    grep -v 'google/go-sev-guest' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
  fi
done

# wails dev's binding generator (golang.org/x/tools/go/packages) does NOT honor
# the /tmp/go.work workspace for in-house TRANSITIVE modules, so it tries to
# fetch them (e.g. go-qrdb@v0.0.0) from GitHub and fails. xkey/go.mod already
# carries committed replaces for go-xkms and go-xkms/sdk/go for this reason;
# the rest became xkey transitive deps after the embedded-qrdb unification.
# Inject the remaining local-path replaces directly into the main module's
# go.mod (always honored by go, workspace or not). The relative paths resolve
# to the bind-mounted siblings (/workspace/xkey/../../go-qrdb => /go-qrdb).
# cleanup() restores the committed file on exit.
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
echo "[entrypoint] Injected in-house module replaces into xkey/go.mod."

# Populate /tmp/go.work.sum for the workspace build list (in-house modules are
# local workspace members, so only public dependencies are fetched).
cd /workspace/xkey
go mod download all
echo "[entrypoint] Go modules downloaded."

# Warm the build cache (compiled export data) for the full build graph with the
# same tags wails uses. The wails binding generator loads packages with
# golang.org/x/tools/go/packages in NeedTypes mode; against a COLD cache it
# fails to obtain export data for the nested in-house generics module and aborts
# with: internal error: package "github.com/jeremyhahn/go-qrdb/sdk/go" without
# types was imported from ".../xkey/pkg/pcr_policy". Pre-building populates the
# export data so the loader resolves types on the first pass.
echo "[entrypoint] Warming Go build cache for wails binding generation..."
go build -tags "ble production webkit2_41" ./... >/dev/null 2>&1 || true
echo "[entrypoint] Build cache warmed."

# ---------------------------------------------------------------------------
# 6. Start wails dev server in background
# ---------------------------------------------------------------------------
# The wails CLI in this image is rebuilt against x/tools v0.45.0 (see Dockerfile),
# which fixes the "package go-qrdb/sdk/go without types" binding-analysis abort,
# so a plain `wails dev` works.
echo "[entrypoint] Starting wails dev server..."
# Do NOT pass the `production` tag to `wails dev`: wails injects its own `dev`
# build tag, and `production` would also compile wails' internal app_production.go,
# colliding with app_dev.go (App.Run/CreateApp redeclared). xkey's GUI gate
# (cmd/xkey/gui_enabled.go: //go:build production || dev || bindings) is satisfied
# by the injected `dev` tag, so the GUI is still enabled.
GONOSUMCHECK='*' GONOSUMDB='*' wails dev -tags "ble,codec_json,pkcs11,webkit2_41" &
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
# E2E_SPEC (optional) narrows the run to specific spec files for fast iteration,
# e.g. `docker compose run -e E2E_SPEC="trust-store.spec.ts" e2e`. Empty = all.
#
# --workers=1: the real-backend harness drives ONE shared xkmsd backend (a
# single-user desktop model — there is no per-session isolation, by design).
# Parallel workers mutating that one backend race each other (e.g. one worker's
# PIV slot-9A cleanup deleting a cert another worker is about to read). Serial
# execution is the correct determinism guarantee for a shared single backend;
# the fast Vite layout suite (window.go undefined, read-only) keeps 4 workers.
#
# --retries=2: tests run against a live `wails dev` server that recompiles and
# GCs in the background; under a long serial sweep a single page.goto can stall
# past navigationTimeout while the dev server is busy. Retries absorb that
# environmental flake without masking real failures (a genuine bug fails all
# attempts). Matches the playwright.config CI default.
npx playwright test --workers=1 --retries=2 ${E2E_SPEC:-} || TEST_EXIT=$?

# ---------------------------------------------------------------------------
# 9. Report results
# ---------------------------------------------------------------------------
if [ "$TEST_EXIT" -eq 0 ]; then
    echo "[entrypoint] All E2E tests passed."
else
    echo "[entrypoint] E2E tests failed with exit code ${TEST_EXIT}."
fi

exit "$TEST_EXIT"
