#!/bin/sh
# Generate TLS certificates and server configuration for bootstrap integration tests.
#
# This script is executed inside the xkms-server container before the daemon starts.
# It produces:
#   /etc/xkms/certs/ca.crt        - Self-signed CA certificate
#   /etc/xkms/certs/ca.key        - CA private key
#   /etc/xkms/certs/server.crt    - Server certificate signed by the CA
#   /etc/xkms/certs/server.key    - Server private key
#   /etc/xkms/certs/noise.pub.hex - Noise server static public key (hex, 64 chars)
#   /etc/xkms/certs/spki.pin      - SPKI SHA-256 pin of the server certificate (hex)
#   /etc/xkms/xkmsd.yaml          - xkmsd daemon configuration

set -eu

CERT_DIR="${CERT_DIR:-/etc/xkms/certs}"
CONFIG_FILE="/etc/xkms/xkmsd.yaml"
DATA_DIR="${XKMS_DATA_DIR:-/data}"
DAYS_VALID=365
HOSTNAME_SAN="bootstrap.test"
CONTAINER_NAME="xkms-server"

# ---------------------------------------------------------------------------
# Step 1: Create directories
# ---------------------------------------------------------------------------

mkdir -p "${CERT_DIR}" "${DATA_DIR}" "${DATA_DIR}/software" "${DATA_DIR}/certs"
echo "Certificate directory: ${CERT_DIR}"
echo "Data directory:        ${DATA_DIR}"

# ---------------------------------------------------------------------------
# Step 2: Generate CA key pair and self-signed certificate
# ---------------------------------------------------------------------------

echo "Generating CA key pair..."
openssl ecparam -genkey -name prime256v1 -out "${CERT_DIR}/ca.key" 2>/dev/null

openssl req -x509 -new -nodes \
    -key "${CERT_DIR}/ca.key" \
    -sha256 \
    -days ${DAYS_VALID} \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/C=US/ST=Test/L=Test/O=go-xkms Test CA/OU=Integration Tests/CN=go-xkms Test CA" \
    2>/dev/null

echo "CA certificate generated: ${CERT_DIR}/ca.crt"

# ---------------------------------------------------------------------------
# Step 3: Generate server key pair and CSR
# ---------------------------------------------------------------------------

echo "Generating server key pair..."
openssl ecparam -genkey -name prime256v1 -out "${CERT_DIR}/server.key" 2>/dev/null

# Create CSR configuration with SANs for both the test hostname and container name
cat > "${CERT_DIR}/server.cnf" << CSRCNF
[req]
default_bits       = 256
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[dn]
C  = US
ST = Test
L  = Test
O  = go-xkms Test Server
CN = ${HOSTNAME_SAN}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME_SAN}
DNS.2 = ${CONTAINER_NAME}
DNS.3 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
CSRCNF

openssl req -new \
    -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -config "${CERT_DIR}/server.cnf" \
    2>/dev/null

# ---------------------------------------------------------------------------
# Step 4: Sign server certificate with CA
# ---------------------------------------------------------------------------

cat > "${CERT_DIR}/server_ext.cnf" << EXTCNF
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME_SAN}
DNS.2 = ${CONTAINER_NAME}
DNS.3 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EXTCNF

openssl x509 -req \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -days ${DAYS_VALID} \
    -sha256 \
    -extfile "${CERT_DIR}/server_ext.cnf" \
    2>/dev/null

echo "Server certificate generated: ${CERT_DIR}/server.crt"

# Clean up temporary files
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/server.cnf" "${CERT_DIR}/server_ext.cnf" "${CERT_DIR}/ca.srl"

# Set file permissions
chmod 644 "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt"
chmod 600 "${CERT_DIR}/ca.key" "${CERT_DIR}/server.key"

# ---------------------------------------------------------------------------
# Step 5: Compute SPKI SHA-256 pin for the server certificate
# ---------------------------------------------------------------------------

SPKI_PIN=$(openssl x509 -in "${CERT_DIR}/server.crt" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null \
    | awk '{print $NF}')

echo "${SPKI_PIN}" > "${CERT_DIR}/spki.pin"
echo "SPKI pin: ${SPKI_PIN}"

# ---------------------------------------------------------------------------
# Step 6: Generate Noise static key pair and export public key
#
# The Noise_NK pattern requires the server to have a Curve25519 static key.
# The server config takes the 32-byte private key (hex encoded, 64 chars).
# The test client needs the corresponding 32-byte public key (hex encoded).
#
# We derive the public key from the private key using scalar base
# multiplication on Curve25519. Since openssl does not natively support
# this operation, we use a small Go helper that leverages golang.org/x/crypto.
# ---------------------------------------------------------------------------

# Generate a 32-byte Curve25519 private key
NOISE_PRIVATE_HEX=$(openssl rand -hex 32)

NOISE_KEY_DIR=$(mktemp -d)
cat > "${NOISE_KEY_DIR}/derive.go" << 'GOEOF'
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

func main() {
	privHex := os.Args[1]
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode error: %v\n", err)
		os.Exit(1)
	}
	pub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "x25519 error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(hex.EncodeToString(pub))
}
GOEOF

# Build and run the key derivation helper
NOISE_PUBLIC_HEX=""
if command -v go >/dev/null 2>&1; then
    cd "${NOISE_KEY_DIR}"
    go mod init noise-derive >/dev/null 2>&1
    go get golang.org/x/crypto/curve25519 >/dev/null 2>&1
    if go build -o derive derive.go 2>/dev/null; then
        NOISE_PUBLIC_HEX=$(./derive "${NOISE_PRIVATE_HEX}")
    fi
    cd /
fi

# Clean up temp directory
rm -rf "${NOISE_KEY_DIR}"

if [ -z "${NOISE_PUBLIC_HEX}" ]; then
    echo "ERROR: Failed to derive Noise public key from private key"
    exit 1
fi

# Write the public key for the test client (shared via Docker volume)
echo "${NOISE_PUBLIC_HEX}" > "${CERT_DIR}/noise.pub.hex"
chmod 644 "${CERT_DIR}/noise.pub.hex"
echo "Noise public key: ${NOISE_PUBLIC_HEX}"

# ---------------------------------------------------------------------------
# Step 7: Write xkmsd configuration file
#
# The Noise static_key_hex takes the 32-byte private key only (64 hex chars).
# The server's DecodeStaticKey derives the public key via Curve25519 scalar
# base multiplication at startup.
# ---------------------------------------------------------------------------

echo "Writing server configuration to ${CONFIG_FILE}..."

cat > "${CONFIG_FILE}" << YAMLEOF
# xkmsd configuration for bootstrap integration tests
# Auto-generated by generate-test-certs.sh

server:
  host: 0.0.0.0
  rest_port: 8443
  noise_port: 8445

protocols:
  unix: false
  rest: true
  grpc: false
  quic: false
  mcp: false
  noise: true

logging:
  level: debug
  format: json

tls:
  enabled: true
  cert_file: ${CERT_DIR}/server.crt
  key_file: ${CERT_DIR}/server.key
  ca_file: ${CERT_DIR}/ca.crt

auth:
  enabled: false

ratelimit:
  enabled: false

metrics:
  enabled: false
  path: /metrics
  port: 9090

health:
  enabled: true
  path: /health

storage:
  backend: file
  path: ${DATA_DIR}

rng:
  mode: software

default_backend: software

backends:
  software:
    enabled: true
    path: ${DATA_DIR}/software

barrier:
  enabled: true
  root_key_path: ${DATA_DIR}/barrier

bootstrap:
  noise:
    enabled: true
    static_key_hex: ${NOISE_PRIVATE_HEX}
  spki:
    enabled: true
    pin_sha256: ${SPKI_PIN}
  dane:
    enabled: true
    hostname: ${HOSTNAME_SAN}
    port: 8443
YAMLEOF

chmod 644 "${CONFIG_FILE}"

# ---------------------------------------------------------------------------
# Step 8: Print summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "CA certificate:     ${CERT_DIR}/ca.crt"
echo "CA key:             ${CERT_DIR}/ca.key"
echo "Server certificate: ${CERT_DIR}/server.crt"
echo "Server key:         ${CERT_DIR}/server.key"
echo "Noise public key:   ${CERT_DIR}/noise.pub.hex"
echo "SPKI pin:           ${CERT_DIR}/spki.pin"
echo "Server config:      ${CONFIG_FILE}"
echo ""
echo "Server certificate details:"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -subject -issuer -dates 2>/dev/null
echo ""
echo "Subject Alternative Names:"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -ext subjectAltName 2>/dev/null || true
