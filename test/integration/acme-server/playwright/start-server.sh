#!/bin/bash
set -euo pipefail

# Build and start the trusted-acme-server for E2E testing.
# This script is called by Playwright's webServer config.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

SERVER_BIN="${SCRIPT_DIR}/trusted-acme-server"
SERVER_PORT="${E2E_SERVER_PORT:-9443}"
WORK_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORK_DIR" "$SERVER_BIN" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"/{data,qrdb,tls,run}

# Generate self-signed TLS cert for testing
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout "$WORK_DIR/tls/server.key" \
    -out "$WORK_DIR/tls/server.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

# Build the server with required tags
echo "Building trusted-acme-server..." >&2
cd "$PROJECT_DIR"
go build -tags "local,iam,raft,timeseries,grpc,codec_json,codec_msgpack,codec_cbor,codec_yaml" \
    -o "$SERVER_BIN" ./cmd/trusted-acme-server

echo "Starting trusted-acme-server on port $SERVER_PORT..." >&2

# Configure via environment variables (TRUSTEDCA_ prefix, dots become underscores)
export TRUSTEDCA_ADMIN_ENABLED=true
export TRUSTEDCA_ADMIN_REST_ADDR=":${SERVER_PORT}"
export TRUSTEDCA_ADMIN_GRPC_ADDR=":0"
export TRUSTEDCA_ADMIN_GRPC_UNIX_PATH="$WORK_DIR/run/trusted-ca-grpc.sock"
export TRUSTEDCA_ADMIN_HTTP_UNIX_PATH="$WORK_DIR/run/trusted-ca-rest.sock"
export TRUSTEDCA_ADMIN_QUIC_ADDR=":0"
export TRUSTEDCA_ADMIN_MCP_ADDR=":0"
export TRUSTEDCA_SERVER_HTTPS_ADDR=":8443"
export TRUSTEDCA_SERVER_EXTERNAL_URL="https://localhost:8443"
export TRUSTEDCA_SERVER_TLS_CERT_FILE="$WORK_DIR/tls/server.crt"
export TRUSTEDCA_SERVER_TLS_KEY_FILE="$WORK_DIR/tls/server.key"
export TRUSTEDCA_STORAGE_PATH="$WORK_DIR/data"
export TRUSTEDCA_QRDB_MODE=standalone
export TRUSTEDCA_QRDB_PROTOCOL=embedded
export TRUSTEDCA_QRDB_DATA_DIR="$WORK_DIR/qrdb"
export TRUSTEDCA_QRDB_UNIX_SOCKET_PATH="$WORK_DIR/run/qrdb.sock"
export TRUSTEDCA_LOGGING_LEVEL=warn
export TRUSTEDCA_RATE_LIMIT_REQUESTS=10000

# Run the server (Playwright manages process lifecycle)
exec "$SERVER_BIN"
