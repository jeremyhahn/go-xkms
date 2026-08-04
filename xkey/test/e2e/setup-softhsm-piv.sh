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

# Initializes a dedicated SoftHSM2 token with pre-loaded PIV test certificates.
#
# PIV slot → CKA_ID mapping (YubiKey convention):
#   9A (Authentication)    → 0x01
#   9C (Digital Signature) → 0x02
#   9D (Key Management)    → 0x03
#   9E (Card Authentication) → 0x04
#
# Idempotency is per-object, by design: this script NEVER deletes an existing
# token. A long-running consumer (e.g. the xkey Wails dev server used by the
# Playwright e2e tier) may hold an open PKCS#11 session against this exact
# token while another test file consumes (deletes) one slot's cert/key pair
# and this script is re-run to restore it. Deleting and recreating the whole
# token would invalidate that live session (new token UUID / possibly a new
# slot ID). Instead, each of the four PIV slots is checked independently by
# its CKA_ID and only regenerated if missing — the token itself, once
# created, is never destroyed by this script.
#
# Exports:
#   SOFTHSM_PIV_SLOT     — slot number assigned to the e2e-piv-test token
#   SOFTHSM_PIV_PIN      — user PIN (123456)
#   SOFTHSM_PIV_LIBRARY  — path to the SoftHSM2 PKCS#11 shared library

set -euo pipefail

SOFTHSM_LIB="/usr/lib/softhsm/libsofthsm2.so"
TOKEN_LABEL="e2e-piv-test"
SO_PIN="12345678"
USER_PIN="123456"
CERT_DIR="/tmp/e2e-piv-certs"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pkcs11() {
    pkcs11-tool --module "${SOFTHSM_LIB}" "$@"
}

# cert_exists ID — true if a certificate object with the given CKA_ID
# (two hex digits, e.g. "01") is already present on the token.
cert_exists() {
    local id="$1"
    pkcs11 --token-label "${TOKEN_LABEL}" -O --type cert --id "${id}" 2>/dev/null \
        | grep -q "Certificate Object"
}

# ---------------------------------------------------------------------------
# 1. Check prerequisites
# ---------------------------------------------------------------------------
if [ ! -f "${SOFTHSM_LIB}" ]; then
    echo "[setup-softhsm-piv] ERROR: SoftHSM2 library not found at ${SOFTHSM_LIB}"
    exit 1
fi

for cmd in softhsm2-util pkcs11-tool openssl; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "[setup-softhsm-piv] ERROR: required command '${cmd}' not found"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 2. Create the token only if it does not already exist. Never delete it —
#    see the idempotency note in the file header.
# ---------------------------------------------------------------------------
if softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*${TOKEN_LABEL}"; then
    echo "[setup-softhsm-piv] Token '${TOKEN_LABEL}' already exists."
else
    echo "[setup-softhsm-piv] Initializing SoftHSM2 token '${TOKEN_LABEL}'..."
    softhsm2-util --init-token --free \
        --label "${TOKEN_LABEL}" \
        --so-pin "${SO_PIN}" \
        --pin "${USER_PIN}"
fi

# Resolve the assigned slot number by finding the Slot line that precedes our token label.
SLOT=$(softhsm2-util --show-slots 2>/dev/null \
    | grep -B 20 "Label:.*${TOKEN_LABEL}" \
    | grep "^Slot " | tail -1 | awk '{print $2}')
if [ -z "${SLOT}" ]; then
    echo "[setup-softhsm-piv] ERROR: could not resolve slot for token '${TOKEN_LABEL}'"
    exit 1
fi
echo "[setup-softhsm-piv] Token is in slot ${SLOT}."

# ---------------------------------------------------------------------------
# 3. Generate self-signed test certificates for any missing PIV slot
# ---------------------------------------------------------------------------
mkdir -p "${CERT_DIR}"

generate_rsa_cert() {
    local name="$1"
    local cn="$2"
    local id="$3"

    if cert_exists "${id}"; then
        echo "[setup-softhsm-piv] ${cn} (CKA_ID=0x${id}) already present, skipping."
        return
    fi

    local key="${CERT_DIR}/${name}.key"
    local cert="${CERT_DIR}/${name}.crt"

    echo "[setup-softhsm-piv] Generating RSA 2048 certificate for ${cn} (CKA_ID=0x${id})..."

    openssl req -x509 -newkey rsa:2048 -keyout "${key}" -out "${cert}" \
        -days 3650 -nodes -subj "/CN=${cn}"

    # Import private key.
    pkcs11 --write-object "${key}" --type privkey \
        --slot "${SLOT}" --pin "${USER_PIN}" \
        --id "${id}" --label "${cn}"

    # Import certificate.
    pkcs11 --write-object "${cert}" --type cert \
        --slot "${SLOT}" --pin "${USER_PIN}" \
        --id "${id}" --label "${cn}"
}

generate_ec_cert() {
    local name="$1"
    local cn="$2"
    local id="$3"

    if cert_exists "${id}"; then
        echo "[setup-softhsm-piv] ${cn} (CKA_ID=0x${id}) already present, skipping."
        return
    fi

    local key="${CERT_DIR}/${name}.key"
    local cert="${CERT_DIR}/${name}.crt"

    echo "[setup-softhsm-piv] Generating ECDSA P-256 certificate for ${cn} (CKA_ID=0x${id})..."

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${key}" -out "${cert}" \
        -days 3650 -nodes -subj "/CN=${cn}"

    # Import private key.
    pkcs11 --write-object "${key}" --type privkey \
        --slot "${SLOT}" --pin "${USER_PIN}" \
        --id "${id}" --label "${cn}"

    # Import certificate.
    pkcs11 --write-object "${cert}" --type cert \
        --slot "${SLOT}" --pin "${USER_PIN}" \
        --id "${id}" --label "${cn}"
}

# Slot 9A — PIV Authentication (RSA 2048, CKA_ID=0x01)
generate_rsa_cert "piv-auth"   "PIV Authentication Test"  "01"

# Slot 9C — Digital Signature (RSA 2048, CKA_ID=0x02)
generate_rsa_cert "piv-sign"   "Digital Signature Test"   "02"

# Slot 9D — Key Management (RSA 2048, CKA_ID=0x03)
generate_rsa_cert "piv-keymgmt" "Key Management Test"     "03"

# Slot 9E — Card Authentication (ECDSA P-256, CKA_ID=0x04)
generate_ec_cert  "piv-cardauth" "Card Authentication Test" "04"

# ---------------------------------------------------------------------------
# 4. Clean up temporary certificate files
# ---------------------------------------------------------------------------
rm -rf "${CERT_DIR}"
echo "[setup-softhsm-piv] Temporary certificate files removed."

# ---------------------------------------------------------------------------
# 5. Export environment variables
# ---------------------------------------------------------------------------
export SOFTHSM_PIV_SLOT="${SLOT}"
export SOFTHSM_PIV_PIN="${USER_PIN}"
export SOFTHSM_PIV_LIBRARY="${SOFTHSM_LIB}"

echo "[setup-softhsm-piv] Done."
echo "[setup-softhsm-piv] SOFTHSM_PIV_SLOT=${SOFTHSM_PIV_SLOT}"
echo "[setup-softhsm-piv] SOFTHSM_PIV_PIN=${SOFTHSM_PIV_PIN}"
echo "[setup-softhsm-piv] SOFTHSM_PIV_LIBRARY=${SOFTHSM_PIV_LIBRARY}"
