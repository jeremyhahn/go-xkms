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
SERVER_PID=""

cleanup() {
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
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

ratelimit:
  enabled: false

# xkmsd init writes the admin credential and the unified TLS certificate here;
# open-server-barrier.sh finds the certificate under <state dir>/storage.
datastore:
  path: "$WORK_DIR/storage"

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

# Initialize the barrier as an operator does before a first boot: the SO PIN
# becomes its passphrase and travels in the environment, never in the config.
SO_PIN="${E2E_SO_PIN:-e2e-test-so-pin}"
XKMS_SO_PIN="$SO_PIN" "$SERVER_BIN" init --config "$CONFIG_FILE" \
    --data-dir "$WORK_DIR/storage" --hostname localhost --admin-factor mtls >&2

echo "Starting xkmsd (ACME listener on :${SERVER_PORT})..." >&2

# Run the server (Playwright manages process lifecycle). It boots sealed, so
# open its barrier through the sealed window with the helper that unseals the
# compose xkms-server; the ACME listener Playwright waits for comes up after.
env -u XKMS_SO_PIN "$SERVER_BIN" --config "$CONFIG_FILE" &
SERVER_PID=$!
XKMS_SERVER_WINDOW_URL="https://localhost:18443" \
    XKMS_SERVER_STATE_DIR="$WORK_DIR" \
    XKMS_SERVER_BARRIER_SECRET="$SO_PIN" \
    bash "$PROJECT_DIR/build/docker/devcontainer/scripts/open-server-barrier.sh" >&2
wait "$SERVER_PID"
