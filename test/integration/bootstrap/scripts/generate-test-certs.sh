#!/bin/sh
# Generate TLS certificates and server configuration for bootstrap integration tests.
#
# This script is executed inside the xkms-server container before the daemon starts.
# It produces:
#   /etc/xkms/certs/ca.crt        - Self-signed CA certificate
#   /etc/xkms/certs/ca.key        - CA private key
#   /etc/xkms/certs/server.crt    - Server certificate signed by the CA
#   /etc/xkms/certs/server.key    - Server private key
#   /etc/xkms/certs/spki.pin      - SPKI SHA-256 pin of the server certificate (hex)
#   /etc/xkms/xkmsd.yaml          - xkmsd daemon configuration
#
# It does NOT produce a Noise static key: the listener generates or unseals
# its own (go-xkms#35), so there is nothing for this script to pre-determine.
# test/integration/bootstrap discovers the running server's actual Noise/P-256
# public keys after boot, through the admin API
# (`xkmsctl bootstrap show-keys` / BootstrapListenerKeys, go-xkms#632) — see
# discoverBootstrapKeys in test/integration/bootstrap/testutil.go.

set -eu

CERT_DIR="${CERT_DIR:-/etc/xkms/certs}"
CONFIG_FILE="/etc/xkms/xkmsd.yaml"
DATA_DIR="${TEST_DATA_DIR:-/data}"
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

# Build the full chain (leaf + CA) for the server to present. DANE-TA
# (TLSA usage=2) verification per RFC 7671 Section 5.2.2 requires the trust
# anchor certificate to be present in the TLS-presented chain, so the server
# must serve fullchain.crt rather than the bare leaf.
cat "${CERT_DIR}/server.crt" "${CERT_DIR}/ca.crt" > "${CERT_DIR}/fullchain.crt"
echo "Full chain generated: ${CERT_DIR}/fullchain.crt"

# Clean up temporary files
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/server.cnf" "${CERT_DIR}/server_ext.cnf" "${CERT_DIR}/ca.srl"

# Set file permissions
chmod 644 "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt" "${CERT_DIR}/fullchain.crt"
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
# Step 6: Write xkmsd configuration file
#
# There is no config field for the listener's Noise/P256 static key
# (go-xkms#35 removed bootstrap.noise.static_key_hex / static_key_file /
# p256_static_key_hex / p256_static_key_file outright): the server generates
# and seals its own key on first boot. This script has nothing to
# pre-determine or write for it; test/integration/bootstrap discovers the
# real key after boot, through the admin API (go-xkms#632) — see
# discoverBootstrapKeys in test/integration/bootstrap/testutil.go.
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
  # fullchain.crt (leaf + CA) so DANE-TA clients can match the trust anchor
  # in the presented chain (RFC 7671 Section 5.2.2).
  cert_file: ${CERT_DIR}/fullchain.crt
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
echo "SPKI pin:           ${CERT_DIR}/spki.pin"
echo "Server config:      ${CONFIG_FILE}"
echo ""
echo "Server certificate details:"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -subject -issuer -dates 2>/dev/null
echo ""
echo "Subject Alternative Names:"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -ext subjectAltName 2>/dev/null || true
