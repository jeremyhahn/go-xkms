#!/bin/bash
# test-oidc-full-flow.sh - Full end-to-end OIDC login test with exec script
# Tests the complete flow: login -> callback -> token exchange -> exec script

set -e

TEST_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XKEY_DIR="$(dirname "$TEST_SCRIPT_DIR")"
XKEY_BIN="${XKEY_DIR}/xkey"
TEST_STORE="/tmp/xkey-oidc-test-$$"
TEST_EXEC_SCRIPT="${TEST_SCRIPT_DIR}/test-exec.sh"
OUTPUT_FILE="$TEST_STORE/login-output.txt"

cleanup() {
    rm -rf "$TEST_STORE"
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Full OIDC Login Flow Test ==="
echo ""

# Check prerequisites
if [ ! -x "$XKEY_BIN" ]; then
    echo "ERROR: xkey binary not found at $XKEY_BIN"
    echo "Build it with: cd $XKEY_DIR && go build -o xkey ./cmd/xkey/..."
    exit 1
fi

if ! curl -s http://localhost:8080/default/.well-known/openid-configuration > /dev/null 2>&1; then
    echo "ERROR: Mock OAuth2 server not running on http://localhost:8080"
    echo "Start it with: docker run -d --name mock-oauth2 -p 8080:8080 ghcr.io/navikt/mock-oauth2-server:latest"
    exit 1
fi

echo "1. Prerequisites OK"
echo "   - xkey binary: $XKEY_BIN"
echo "   - Mock OAuth2 server: http://localhost:8080/default"
echo "   - Test store: $TEST_STORE"
echo ""

# Prepare test directory
mkdir -p "$TEST_STORE"

# Start the login flow in background
echo "2. Starting OIDC login flow..."
"$XKEY_BIN" oidc login \
  --issuer http://localhost:8080/default \
  --client-id test-client \
  --token-store "${TEST_STORE}/tokens.json" \
  --exec "$TEST_EXEC_SCRIPT" \
  --no-browser > "$OUTPUT_FILE" 2>&1 &
LOGIN_PID=$!

# Wait for the callback server to start and URL to be printed
sleep 2

# Extract authorization URL from output
AUTH_URL=$(grep -oP 'http://localhost:8080/default/authorize\S+' "$OUTPUT_FILE" || echo "")

if [ -z "$AUTH_URL" ]; then
    echo "ERROR: Could not extract authorization URL from output"
    cat "$OUTPUT_FILE"
    exit 1
fi

echo "   Authorization URL extracted"

# Extract state from the authorization URL
STATE=$(echo "$AUTH_URL" | grep -oP 'state=\K[^&]+' || echo "")

if [ -z "$STATE" ]; then
    echo "ERROR: Could not extract state from authorization URL"
    exit 1
fi

echo "   - State: ${STATE:0:20}..."
echo ""

# Simulate browser completing the authorization
echo "3. Simulating browser callback..."
CALLBACK_RESULT=$(curl -s "http://localhost:8085/callback?code=mock-auth-code&state=$STATE")

if [[ "$CALLBACK_RESULT" != *"Authentication Successful"* ]]; then
    echo "ERROR: Callback failed: $CALLBACK_RESULT"
    exit 1
fi

echo "   Callback: Authentication Successful"
echo ""

# Wait for the login process to complete
echo "4. Waiting for login flow to complete..."
wait $LOGIN_PID
LOGIN_EXIT=$?

echo ""
echo "5. Login output:"
echo "---"
cat "$OUTPUT_FILE"
echo "---"
echo ""

if [ $LOGIN_EXIT -ne 0 ]; then
    echo "ERROR: Login process exited with code $LOGIN_EXIT"
    exit 1
fi

# Verify tokens were stored
echo "6. Verifying token storage..."
if [ -f "${TEST_STORE}/tokens.json" ]; then
    echo "   Token file created successfully"
    echo ""
    echo "   Token contents:"
    jq -r '.tokens[0] | "     - Provider: \(.issuer)\n     - Expires At: \(.expires_at)"' "${TEST_STORE}/tokens.json"
else
    echo "ERROR: Token file not created!"
    exit 1
fi

echo ""
echo "=== Full OIDC Flow Test PASSED ==="
