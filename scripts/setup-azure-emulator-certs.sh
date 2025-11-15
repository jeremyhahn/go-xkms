#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../.azure-emulator/certs"
CERT_PASSWORD="emulator"

echo "→ Setting up Azure Key Vault emulator certificates..."

# Create certs directory
mkdir -p "${CERTS_DIR}"

# Generate self-signed certificate
if [ ! -f "${CERTS_DIR}/emulator.pfx" ]; then
    echo "  Generating SSL certificate..."

    # Generate private key
    openssl genrsa -out "${CERTS_DIR}/emulator.key" 2048

    # Generate certificate signing request with proper SANs
    openssl req -new -key "${CERTS_DIR}/emulator.key" \
        -out "${CERTS_DIR}/emulator.csr" \
        -subj "/C=US/ST=Test/L=Test/O=AzureKeyVaultEmulator/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1"

    # Generate self-signed certificate (valid for 1 year)
    openssl x509 -req -days 365 \
        -in "${CERTS_DIR}/emulator.csr" \
        -signkey "${CERTS_DIR}/emulator.key" \
        -out "${CERTS_DIR}/emulator.crt" \
        -copy_extensions copy

    # Create PFX file (PKCS#12) with password
    openssl pkcs12 -export \
        -out "${CERTS_DIR}/emulator.pfx" \
        -inkey "${CERTS_DIR}/emulator.key" \
        -in "${CERTS_DIR}/emulator.crt" \
        -passout pass:${CERT_PASSWORD}

    # Clean up intermediate files
    rm -f "${CERTS_DIR}/emulator.csr"

    echo "✓ SSL certificate generated:"
    echo "   PFX: ${CERTS_DIR}/emulator.pfx"
    echo "   CRT: ${CERTS_DIR}/emulator.crt"
    echo "   KEY: ${CERTS_DIR}/emulator.key"
    echo "   Password: ${CERT_PASSWORD}"
else
    echo "✓ SSL certificates already exist"
fi

echo "✓ Azure Key Vault emulator certificates ready"
