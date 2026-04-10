#!/bin/bash
# test-oidc-exec.sh - Integration test for OIDC exec functionality
# Simulates what xkey oidc login does after obtaining tokens

set -e

TEST_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_EXEC_SCRIPT="${TEST_SCRIPT_DIR}/test-exec.sh"

echo "=== OIDC Exec Integration Test ==="
echo ""

# Check if mock-oauth2 server is running
if ! curl -s http://localhost:8080/default/.well-known/openid-configuration > /dev/null 2>&1; then
    echo "ERROR: Mock OAuth2 server not running on http://localhost:8080"
    echo "Start it with: docker run -d --name mock-oauth2 -p 8080:8080 ghcr.io/navikt/mock-oauth2-server:latest"
    exit 1
fi

echo "1. Mock OAuth2 server is running"

# Get tokens from mock server
echo "2. Obtaining tokens from mock server..."
CODE_VERIFIER=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 43)
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/default/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=test-client&code=fake-code&redirect_uri=http://localhost:8085/callback&code_verifier=${CODE_VERIFIER}")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo "ERROR: Failed to get tokens from mock server"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "   - Access Token: ${ACCESS_TOKEN:0:50}..."
echo "   - ID Token: ${ID_TOKEN:0:50}..."
echo "   - Refresh Token: $REFRESH_TOKEN"
echo "   - Expires In: $EXPIRES_IN seconds"

# Decode ID token to get claims (no signature verification, just base64)
ID_TOKEN_PAYLOAD=$(echo "$ID_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null || true)
SUBJECT=$(echo "$ID_TOKEN_PAYLOAD" | jq -r '.sub // empty')
ISSUER=$(echo "$ID_TOKEN_PAYLOAD" | jq -r '.iss // empty')

echo ""
echo "3. ID Token claims:"
echo "   - Subject: $SUBJECT"
echo "   - Issuer: $ISSUER"

# Build payload JSON (matching OIDCExecPayload structure)
EXPIRES_AT=$(date -d "+$EXPIRES_IN seconds" --iso-8601=seconds 2>/dev/null || date -v+${EXPIRES_IN}S +%Y-%m-%dT%H:%M:%S%z)
PAYLOAD_JSON=$(cat <<EOF
{
  "provider": "$ISSUER",
  "issuer": "$ISSUER",
  "client_id": "test-client",
  "access_token": "$ACCESS_TOKEN",
  "refresh_token": "$REFRESH_TOKEN",
  "id_token": "$ID_TOKEN",
  "expires_at": "$EXPIRES_AT",
  "expires_in": $EXPIRES_IN,
  "scopes": ["openid", "profile", "email"],
  "subject": "$SUBJECT",
  "email": "test@example.com",
  "name": "Test User"
}
EOF
)

echo ""
echo "4. Executing test script with OIDC environment..."
echo "   Script: $TEST_EXEC_SCRIPT"
echo ""
echo "--- BEGIN SCRIPT OUTPUT ---"

# Execute the test script with environment variables (matching executeOIDCScript behavior)
OIDC_PROVIDER="$ISSUER" \
OIDC_ISSUER="$ISSUER" \
OIDC_CLIENT_ID="test-client" \
OIDC_ACCESS_TOKEN="$ACCESS_TOKEN" \
OIDC_REFRESH_TOKEN="$REFRESH_TOKEN" \
OIDC_ID_TOKEN="$ID_TOKEN" \
OIDC_EXPIRES_AT="$EXPIRES_AT" \
OIDC_EXPIRES_IN="$EXPIRES_IN" \
OIDC_SCOPES="openid profile email" \
OIDC_SUBJECT="$SUBJECT" \
OIDC_EMAIL="test@example.com" \
OIDC_NAME="Test User" \
bash -c "echo '$PAYLOAD_JSON' | $TEST_EXEC_SCRIPT"

echo "--- END SCRIPT OUTPUT ---"
echo ""
echo "5. Test completed successfully!"
