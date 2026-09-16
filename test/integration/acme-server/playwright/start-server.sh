#!/bin/bash
set -euo pipefail

# Build and start xkmsd (with its embedded ACME server) for E2E testing.
# This script is called by Playwright's webServer config.
#
# The ACME protocol surface (RFC 8555 directory/account/order/challenge/cert
# endpoints) now lives inside cmd/xkmsd (see cmd/xkmsd/acme.go), started via
# the "acme:" section of the daemon's YAML configuration -- it is no longer a
# standalone cmd/trusted-acme-server binary.
#
# NOTE: xkmsd does not expose an admin REST API, an admin SPA ("/ui/admin/"),
# a tenant API ("/api/v1/tenants"), or the unauthenticated first-boot setup
# endpoints ("/admin/setup/*") that the trusted-acme-server used to serve.
# Those surfaces are not wired into xkmsd (see the task report); pointing
# this harness at xkmsd only restores the underlying ACME protocol listener.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

SERVER_BIN="${SCRIPT_DIR}/xkmsd"
SERVER_PORT="${E2E_SERVER_PORT:-9443}"
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORK_DIR" "$SERVER_BIN" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"/{data,keys,ca,acme,tls,run}

# Generate a self-signed TLS cert for the dedicated ACME HTTPS listener.
# (cmd/xkmsd's ACME integration does not yet support acme.reuse_tls; see
# buildACMETLSConfig in cmd/xkmsd/acme.go.)
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout "$WORK_DIR/tls/acme.key" \
    -out "$WORK_DIR/tls/acme.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

CONFIG_FILE="$WORK_DIR/xkmsd.yaml"
cat > "$CONFIG_FILE" <<EOF
server:
  host: "127.0.0.1"
  rest_port: 18443
  grpc_port: 18444
  quic_port: 18445
  mcp_port: 18446

protocols:
  rest: true
  grpc: false
  quic: false
  mcp: false

logging:
  level: "warn"
  format: "json"

tls:
  enabled: true
  server_cn: "localhost"

auth:
  enabled: true
  type: "composite"

barrier:
  enabled: true
  strategy: "passphrase"
  passphrase: "e2e-test-barrier"

ratelimit:
  enabled: false

storage:
  backend: "qrdb"
  path: "$WORK_DIR/data"

default_backend: "software"

backends:
  software:
    enabled: true
    path: "$WORK_DIR/keys"

ca:
  identity:
    - subject:
        cn: "E2E Test Root CA"
        organization: "go-xkms E2E Tests"
        country: "US"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc:
            curve: "P-256"
          hash: "SHA-256"
          signature-algorithm: "ECDSAWithSHA256"
          store: "software"
          key-type: "CA"
      keystore-type: "software"
      is-root: true
      max-path-length: 1
  selected-ca: 0
  default-validity-days: 365
  include-localhost-sans: true
  home-dir: "$WORK_DIR/ca"

acme:
  enabled: true
  https_addr: ":${SERVER_PORT}"
  external_url: "https://localhost:${SERVER_PORT}"
  directory_path: "/acme"
  keystore_backend: "software"
  data_dir: "$WORK_DIR/acme"
  reuse_tls: false
  tls:
    cert_file: "$WORK_DIR/tls/acme.crt"
    key_file: "$WORK_DIR/tls/acme.key"
  challenges:
    http01: true
EOF

# Build xkmsd with the same protocol tags the old trusted-acme-server build used.
echo "Building xkmsd..." >&2
cd "$PROJECT_DIR"
go build -tags "local,iam,raft,timeseries,grpc,codec_json,codec_msgpack,codec_cbor,codec_yaml" \
    -o "$SERVER_BIN" ./cmd/xkmsd

echo "Starting xkmsd (ACME listener on :${SERVER_PORT})..." >&2

# Run the server (Playwright manages process lifecycle)
exec "$SERVER_BIN" --config "$CONFIG_FILE"
