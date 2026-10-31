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

# Clean keystore state for a deterministic run.
rm -rf ./.runtime/data
mkdir -p ./.runtime/data/software

echo "[run-server] launching ${XKMSD_BIN} on https://localhost:18443" >&2
exec env XKMS_CONFIG="$(pwd)/config.yaml" "${XKMSD_BIN}"
