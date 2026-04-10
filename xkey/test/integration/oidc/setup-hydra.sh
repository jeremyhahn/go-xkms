#!/bin/bash
# Setup script for xkey OIDC integration tests
# Creates OAuth2 clients in ORY Hydra for testing
set -e

HYDRA_ADMIN_URL="${HYDRA_ADMIN_URL:-http://127.0.0.1:4445}"

echo "Setting up Hydra test clients at ${HYDRA_ADMIN_URL}..."

# Create OAuth client for client credentials flow
# Used for machine-to-machine authentication testing
echo "Creating client credentials client..."
CLIENT_CC=$(hydra create oauth2-client \
    --endpoint "${HYDRA_ADMIN_URL}" \
    --name xkey-test-client-credentials \
    --secret xkey-test-secret \
    --grant-type client_credentials \
    --response-type token \
    --scope "api:read,api:write" \
    --token-endpoint-auth-method client_secret_post \
    --format json)

CLIENT_CC_ID=$(echo "$CLIENT_CC" | jq -r '.client_id')
echo "Created client credentials client: $CLIENT_CC_ID"

# Create OAuth client for authorization code flow with PKCE
# Used for interactive login testing (simulated)
echo "Creating authorization code client..."
CLIENT_AC=$(hydra create oauth2-client \
    --endpoint "${HYDRA_ADMIN_URL}" \
    --name xkey-test-authcode \
    --secret xkey-test-authcode-secret \
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --scope "openid,profile,email,offline_access" \
    --redirect-uri http://127.0.0.1:8085/callback,http://localhost:8085/callback \
    --token-endpoint-auth-method client_secret_post \
    --format json)

CLIENT_AC_ID=$(echo "$CLIENT_AC" | jq -r '.client_id')
echo "Created authorization code client: $CLIENT_AC_ID"

# Create OAuth client for OIDC discovery and token validation testing
# Has openid scope and supports client_credentials for testing without interactive auth
echo "Creating OIDC test client..."
CLIENT_OIDC=$(hydra create oauth2-client \
    --endpoint "${HYDRA_ADMIN_URL}" \
    --name xkey-test-oidc \
    --secret xkey-test-oidc-secret \
    --grant-type client_credentials,refresh_token \
    --response-type token \
    --scope "openid,profile,email,offline_access" \
    --token-endpoint-auth-method client_secret_post \
    --format json)

CLIENT_OIDC_ID=$(echo "$CLIENT_OIDC" | jq -r '.client_id')
echo "Created OIDC test client: $CLIENT_OIDC_ID"

# Export environment variables for tests
cat > /tmp/xkey-oidc-test-env.sh << EOF
export XKEY_TEST_HYDRA_PUBLIC_URL="${HYDRA_PUBLIC_URL:-http://127.0.0.1:4444}"
export XKEY_TEST_HYDRA_ADMIN_URL="${HYDRA_ADMIN_URL}"
export XKEY_TEST_CLIENT_CREDENTIALS_ID="${CLIENT_CC_ID}"
export XKEY_TEST_CLIENT_CREDENTIALS_SECRET="xkey-test-secret"
export XKEY_TEST_AUTHCODE_CLIENT_ID="${CLIENT_AC_ID}"
export XKEY_TEST_AUTHCODE_CLIENT_SECRET="xkey-test-authcode-secret"
export XKEY_TEST_OIDC_CLIENT_ID="${CLIENT_OIDC_ID}"
export XKEY_TEST_OIDC_CLIENT_SECRET="xkey-test-oidc-secret"
EOF

echo ""
echo "=========================================="
echo "Hydra is configured and ready for testing"
echo "=========================================="
echo "Public endpoint: ${HYDRA_PUBLIC_URL:-http://127.0.0.1:4444}"
echo "Admin endpoint:  ${HYDRA_ADMIN_URL}"
echo ""
echo "Test clients:"
echo "  Client Credentials: ${CLIENT_CC_ID}"
echo "  Authorization Code: ${CLIENT_AC_ID}"
echo "  OIDC:               ${CLIENT_OIDC_ID}"
echo ""
