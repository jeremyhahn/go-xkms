#!/bin/sh
# Generate the TLS certificate the ACME (RFC 8555) protocol listener needs.
#
# Executed inside the xkmsd container before the daemon starts. The ACME
# listener (acme.https_addr in xkmsd.yaml) is a separate, dedicated HTTPS
# listener that xkmsd does not CA-back the way it does the unified
# REST/admin listener: acme.tls.cert_file/key_file are required whenever
# acme.enabled is true (pkg/config/acme.go's ErrACMEMissingTLS). A
# self-signed certificate is sufficient here — nothing in this suite dials
# the ACME protocol listener directly, only the admin plane on the unified
# listener, which self-issues its own certificate from the embedded CA at
# boot (see xkmsd.yaml's top comment and main_test.go).
#
# Output (under $CERT_DIR, default /etc/xkms/certs):
#   server.crt / server.key - the ACME listener's certificate

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
