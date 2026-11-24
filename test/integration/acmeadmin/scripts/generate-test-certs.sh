#!/bin/sh
# Generate the TLS certificate the ACME protocol listener needs.

set -eu

CERT_DIR="${CERT_DIR:-/etc/xkms/certs}"
DAYS_VALID=365

mkdir -p "${CERT_DIR}"

echo "Generating ACME listener key pair and self-signed certificate..."
openssl ecparam -genkey -name prime256v1 -out "${CERT_DIR}/server.key" 2>/dev/null
openssl req -x509 -new -nodes \
    -key "${CERT_DIR}/server.key" \
    -sha256 -days ${DAYS_VALID} \
    -out "${CERT_DIR}/server.crt" \
    -subj "/C=US/ST=Test/L=Test/O=go-xkms Integration Tests/CN=xkmsd" \
    -addext "subjectAltName=DNS:xkmsd,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null
echo "ACME listener certificate generated: ${CERT_DIR}/server.crt"

chmod 644 "${CERT_DIR}"/*.crt "${CERT_DIR}"/*.key
