#!/bin/bash
set -euo pipefail

# Build and start the acme-client (trusted-acme-client) in serve mode for
# Playwright testing. The desktop GUI apps have no TCP listener of their own
# (their routers mount in-process via the Wails asset handler); only
# `acme-client serve` listens on a real address, so that is the mode
# Playwright must target.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

CLIENT_BIN="${SCRIPT_DIR}/trusted-acme-client"
CLIENT_PKG="./cmd/acme-client"
CLIENT_PORT="${CLIENT_PORT:-18443}"
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORK_DIR" "$CLIENT_BIN" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/storage"

# Create test config with pre-populated accounts and certificates
cat > "$WORK_DIR/config.yaml" << YAML
accounts:
  test-ca:
    directory_url: "https://localhost:8443/acme/directory"
    email: "admin@test.local"
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      store: software
  staging-ca:
    directory_url: "https://acme-staging.example.com/directory"
    email: "ops@staging.local"
    key:
      algorithm: RSA
      rsa:
        bits: 2048
      store: software
certificates:
  web-server:
    account: test-ca
    subject:
      common_name: "web.test.local"
    sans:
      dns_names:
        - "web.test.local"
        - "*.test.local"
    challenge: http-01
    valid_days: 90
  api-server:
    account: staging-ca
    subject:
      common_name: "api.staging.local"
    sans:
      dns_names:
        - "api.staging.local"
    challenge: dns-01
    valid_days: 365
storage:
  backend: file
  path: ${WORK_DIR}/storage
logging:
  level: warn
  format: json
YAML

# Build the client with the gui tag (needed to embed the client SPA that
# `serve` mounts at /ui/client/; the REST API under /api/v1 is what the
# specs actually exercise).
echo "Building acme-client (${CLIENT_PKG})..." >&2
cd "$PROJECT_DIR"
go build -tags "gui,local,iam,codec_json,codec_yaml,codec_cbor,codec_msgpack" \
    -o "$CLIENT_BIN" "$CLIENT_PKG"

echo "Starting acme-client serve on port $CLIENT_PORT..." >&2

# Start in serve mode (no TLS for testing)
exec "$CLIENT_BIN" serve \
    --addr ":${CLIENT_PORT}" \
    --no-tls \
    --config "$WORK_DIR/config.yaml"
