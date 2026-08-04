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
#
# Provisions a sandboxed SoftHSM2 token store for the dev-browser-e2e Wails
# sandbox, entirely under /tmp. The host's real ~/.config/softhsm2 tokens
# (including any pre-existing "e2e-piv-test" or "test-token" tokens created
# outside this sandbox) are NEVER read, modified, or deleted by this script —
# SOFTHSM2_CONF is overridden for every child process below so the SoftHSM2
# shared library resolves an entirely separate token directory.
#
# Idempotent: safe to run on every `make dev-browser-e2e` invocation. Delegates
# the actual token init + PIV certificate provisioning to the project's
# existing test/e2e/setup-softhsm-piv.sh, which already contains the
# idempotency + cert-count checks — this script only supplies the sandboxed
# SOFTHSM2_CONF environment that script runs under.
#
# Exports (for the caller, when sourced):
#   SOFTHSM2_CONF        — sandboxed SoftHSM2 config path (also printed)
#
# Usage:
#   bash scripts/e2e-softhsm-setup.sh
#   E2E_SOFTHSM_DIR=/tmp/other-dir bash scripts/e2e-softhsm-setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XKEY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

E2E_SOFTHSM_DIR="${E2E_SOFTHSM_DIR:-/tmp/xkey-e2e-softhsm}"
TOKEN_DIR="${E2E_SOFTHSM_DIR}/tokens"
SANDBOX_CONF="${E2E_SOFTHSM_DIR}/softhsm2.conf"

echo "[e2e-softhsm-setup] Sandbox dir: ${E2E_SOFTHSM_DIR}"

mkdir -p "${TOKEN_DIR}"

if [ ! -f "${SANDBOX_CONF}" ]; then
    cat > "${SANDBOX_CONF}" <<EOF
# SoftHSM2 configuration - auto-generated for the xkey dev-browser-e2e sandbox.
# This file is isolated under ${E2E_SOFTHSM_DIR} and never touches the host's
# ~/.config/softhsm2 configuration or token store.
directories.tokendir = ${TOKEN_DIR}
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
    echo "[e2e-softhsm-setup] Wrote sandboxed config: ${SANDBOX_CONF}"
else
    echo "[e2e-softhsm-setup] Sandboxed config already exists: ${SANDBOX_CONF}"
fi

export SOFTHSM2_CONF="${SANDBOX_CONF}"

echo "[e2e-softhsm-setup] SOFTHSM2_CONF=${SOFTHSM2_CONF} (sandboxed — host ~/.config/softhsm2 untouched)"
echo "[e2e-softhsm-setup] Provisioning e2e-piv-test token + PIV certificates..."

bash "${XKEY_ROOT}/test/e2e/setup-softhsm-piv.sh"

echo "[e2e-softhsm-setup] Done. Sandbox token ready at ${TOKEN_DIR}."
