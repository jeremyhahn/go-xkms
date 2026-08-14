#!/usr/bin/env bash
# Boot a clean-state xkmsd, with the embedded web UI, for the live web-console
# E2E tier (test/integration/web). Modeled on
# test/integration/webauthn-browser/run-server.sh: Playwright's webServer hook
# invokes this and waits for the configured port to accept connections. The
# data directory is wiped on every run for a deterministic first-boot.
#
# XKMSD_BIN may point at a prebuilt binary (with the "ui" tag and web/dist
# already embedded) to skip the build step entirely. Otherwise:
#   1. the SPA is built and staged to web/dist (`make build-web`), unless
#      XKMS_SKIP_WEB_BUILD=1 and web/dist/index.html already exists — the
#      embed is compile-time (`//go:embed all:dist` in web/embed.go), so a
#      stale or missing web/dist silently ships a stale or UI-less binary.
#   2. xkmsd is built with the "ui" tag plus the software-only tag set the
#      webauthn-browser test uses (no pkcs11/HSM dependency; the SPA doesn't
#      need it).
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../../.. && pwd)"

XKMSD_BIN="${XKMS_XKMSD_BIN:-}"
BUILD_TAGS="ui pkcs8 frost webauthn fido2 codec_cbor codec_json codec_msgpack"

if [[ -z "${XKMSD_BIN}" ]]; then
  if [[ "${XKMS_SKIP_WEB_BUILD:-}" != "1" || ! -f "${REPO_ROOT}/web/dist/index.html" ]]; then
    echo "[run-server] staging web UI (make build-web)..." >&2
    ( cd "${REPO_ROOT}" && make build-web )
  fi
  test -f "${REPO_ROOT}/web/dist/index.html" || {
    echo "[run-server] web/dist/index.html missing after build-web; the UI would not be embedded" >&2
    exit 1
  }

  echo "[run-server] building xkmsd (ui + software-only tags)..." >&2
  XKMSD_BIN="./.runtime/xkmsd"
  mkdir -p ./.runtime
  ( cd "${REPO_ROOT}" && CGO_ENABLED=1 go build -tags "${BUILD_TAGS}" \
      -o "test/integration/web/.runtime/xkmsd" ./cmd/xkmsd/ )
fi

# Clean keystore/CA/audit state for a deterministic run.
rm -rf ./.runtime/data ./.runtime/ca
mkdir -p ./.runtime/data/software ./.runtime/ca

echo "[run-server] launching ${XKMSD_BIN} on https://localhost:18463 (UI at /ui/)" >&2
exec env XKMS_CONFIG="$(pwd)/config.yaml" "${XKMSD_BIN}"
