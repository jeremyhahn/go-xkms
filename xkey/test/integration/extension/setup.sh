#!/bin/bash
set -euo pipefail

export XKEY_HOME="${XKEY_HOME:-/tmp/xkey-test}"
mkdir -p "$XKEY_HOME/data"

echo "=== Setting up xkey extension E2E tests ==="

# Store paths must match what `extension serve --no-barrier` opens:
#   passwords → $XKEY_HOME/data/staticpw  (file backend directory)
#   oath      → $XKEY_HOME/data/oath.json (JSON file store)
PW_STORE="$XKEY_HOME/data/staticpw"
OATH_STORE="$XKEY_HOME/data/oath.json"

# 1. Seed password credentials via CLI
echo "Seeding test credentials..."
xkey password add --name "TestSite Login" --password "test-pass-123" \
  --username "testuser@example.com" --url "http://test-site:8080" \
  --title "Test Site" --store "$PW_STORE" || echo "Credential may already exist"

xkey password add --name "Multi Account 1" --password "multi-pass-1" \
  --username "user1@example.com" --url "http://test-site:8080" \
  --title "Multi 1" --store "$PW_STORE" || echo "Credential may already exist"

xkey password add --name "Multi Account 2" --password "multi-pass-2" \
  --username "user2@example.com" --url "http://test-site:8080" \
  --title "Multi 2" --store "$PW_STORE" || echo "Credential may already exist"

# 2. Seed OATH TOTP
echo "Seeding TOTP account..."
xkey oath add --name "TestSite TOTP" --issuer "test-site" \
  --secret JBSWY3DPEHPK3PXP --store "$OATH_STORE" || echo "OATH account may already exist"

# 3. Verify seeded data
echo "Verifying seeded data..."
xkey password list --store "$PW_STORE"
xkey oath list --store "$OATH_STORE"

# 4. Start headless IPC server (no-barrier mode for testing)
SOCKET="${XKEY_HOME}/xkey.sock"
echo "Starting headless autofill server..."
xkey extension serve \
  --no-barrier \
  --no-auth \
  --socket "$SOCKET" \
  --log-level debug &
SERVE_PID=$!

# 5. Wait for IPC socket
echo "Waiting for IPC socket at ${SOCKET}..."
for i in $(seq 1 30); do
  [ -S "$SOCKET" ] && break
  sleep 0.5
done

if [ ! -S "$SOCKET" ]; then
  echo "ERROR: IPC socket not found after 15s"
  exit 1
fi

# 6. Install native messaging manifest for Chrome (for browser smoke tests)
echo "Installing Chrome native messaging manifest..."
xkey extension install chrome || echo "Manifest install skipped"

echo "=== Setup complete (server PID=$SERVE_PID) ==="
