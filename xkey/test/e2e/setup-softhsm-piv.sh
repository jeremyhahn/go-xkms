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
# 2. Idempotency check — skip only if token exists AND has certificates
# ---------------------------------------------------------------------------
if softhsm2-util --show-slots 2>/dev/null | grep -q "${TOKEN_LABEL}"; then
    CERT_COUNT=$(pkcs11 --token-label "${TOKEN_LABEL}" -O --type cert 2>/dev/null | grep -c "Certificate Object" || true)
    if [ "${CERT_COUNT}" -ge 4 ]; then
        echo "[setup-softhsm-piv] Token '${TOKEN_LABEL}' already populated with ${CERT_COUNT} certs."
        SLOT=$(softhsm2-util --show-slots 2>/dev/null \
            | grep -B 20 "Label:.*${TOKEN_LABEL}" \
            | grep "^Slot " | tail -1 | awk '{print $2}')
        export SOFTHSM_PIV_SLOT="${SLOT:-0}"
        export SOFTHSM_PIV_PIN="${USER_PIN}"
        export SOFTHSM_PIV_LIBRARY="${SOFTHSM_LIB}"
        echo "[setup-softhsm-piv] SOFTHSM_PIV_SLOT=${SOFTHSM_PIV_SLOT}"
        exit 0
    fi
    echo "[setup-softhsm-piv] Token '${TOKEN_LABEL}' exists but has only ${CERT_COUNT} certs, reinitializing..."
    softhsm2-util --delete-token --token "${TOKEN_LABEL}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 3. Initialize the token
# ---------------------------------------------------------------------------
echo "[setup-softhsm-piv] Initializing SoftHSM2 token '${TOKEN_LABEL}'..."
softhsm2-util --init-token --free \
    --label "${TOKEN_LABEL}" \
    --so-pin "${SO_PIN}" \
    --pin "${USER_PIN}"

# Resolve the assigned slot number by finding the Slot line that precedes our token label.
SLOT=$(softhsm2-util --show-slots 2>/dev/null \
    | grep -B 20 "Label:.*${TOKEN_LABEL}" \
    | grep "^Slot " | tail -1 | awk '{print $2}')
if [ -z "${SLOT}" ]; then
    echo "[setup-softhsm-piv] ERROR: could not resolve slot for token '${TOKEN_LABEL}'"
    exit 1
fi
echo "[setup-softhsm-piv] Token initialized in slot ${SLOT}."

# ---------------------------------------------------------------------------
# 4. Generate self-signed test certificates
# ---------------------------------------------------------------------------
mkdir -p "${CERT_DIR}"

generate_rsa_cert() {
    local name="$1"
    local cn="$2"
    local id="$3"

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
# 5. Clean up temporary certificate files
# ---------------------------------------------------------------------------
rm -rf "${CERT_DIR}"
echo "[setup-softhsm-piv] Temporary certificate files removed."

# ---------------------------------------------------------------------------
# 6. Export environment variables
# ---------------------------------------------------------------------------
export SOFTHSM_PIV_SLOT="${SLOT}"
export SOFTHSM_PIV_PIN="${USER_PIN}"
export SOFTHSM_PIV_LIBRARY="${SOFTHSM_LIB}"

echo "[setup-softhsm-piv] Done."
echo "[setup-softhsm-piv] SOFTHSM_PIV_SLOT=${SOFTHSM_PIV_SLOT}"
echo "[setup-softhsm-piv] SOFTHSM_PIV_PIN=${SOFTHSM_PIV_PIN}"
echo "[setup-softhsm-piv] SOFTHSM_PIV_LIBRARY=${SOFTHSM_PIV_LIBRARY}"
