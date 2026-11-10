#!/usr/bin/env bash
# Boot a clean-state xkmsd for the WebAuthn browser ceremony test.
#
# Playwright's webServer hook invokes this and waits for /health. The data
# directory is wiped on every run so each test run starts from an empty
# keystore (deterministic registration ceremonies).
#
# XKMSD_BIN may point at a prebuilt binary; otherwise the binary is built
# locally with the software-only tag set (no pkcs11) which is all the WebAuthn
# RP needs.
set -euo pipefail

cd "$(dirname "$0")"

XKMSD_BIN="${XKMSD_BIN:-}"
BUILD_TAGS="pkcs8 frost webauthn fido2 codec_cbor codec_json codec_msgpack"

if [[ -z "${XKMSD_BIN}" ]]; then
  if [[ -x "../../../build/bin/xkmsd" ]]; then
    XKMSD_BIN="../../../build/bin/xkmsd"
  else
    echo "[run-server] building xkmsd (software-only tags)..." >&2
    XKMSD_BIN="./.runtime/xkmsd"
    mkdir -p ./.runtime
    ( cd ../../.. && CGO_ENABLED=1 go build -tags "${BUILD_TAGS}" \
        -o "test/integration/webauthn-browser/.runtime/xkmsd" ./cmd/xkmsd/ )
  fi
fi

# Clean keystore/CA state for a deterministic run.
rm -rf ./.runtime/data ./.runtime/storage ./.runtime/ca
mkdir -p ./.runtime/data/software ./.runtime/ca

# xkmsd refuses an insecure configuration (cmd/xkmsd: cfg.ComplianceGaps), so
# the RP runs the way test/integration/web does: initialize the barrier as an
# operator does before a first boot (the SO PIN becomes its passphrase and
# travels in the environment, never in the config); init also writes the
# daemon's TLS certificate for localhost, which serves the RP over HTTPS.
SO_PIN="${XKMS_TEST_SO_PIN:-e2e-webauthn-browser-so-pin}"
XKMS_SO_PIN="${SO_PIN}" "${XKMSD_BIN}" init --config "$(pwd)/config.yaml" \
  --data-dir "$(pwd)/.runtime/storage" --hostname localhost --admin-factor mtls >&2

echo "[run-server] launching ${XKMSD_BIN} on https://localhost:18443" >&2
env -u XKMS_SO_PIN XKMS_CONFIG="$(pwd)/config.yaml" "${XKMSD_BIN}" &
server=$!
trap 'kill "${server}" 2>/dev/null || true' EXIT INT TERM

# The daemon boots sealed; open its barrier through the sealed window.
XKMS_SERVER_WINDOW_URL="https://localhost:18443" \
  XKMS_SERVER_STATE_DIR="$(pwd)/.runtime" \
  XKMS_SERVER_BARRIER_SECRET="${SO_PIN}" \
  bash "../../../build/docker/devcontainer/scripts/open-server-barrier.sh" >&2
wait "${server}"