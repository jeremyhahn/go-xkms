#!/bin/bash
# test-exec.sh - Test script for OIDC exec integration
# This script verifies that environment variables are passed correctly

echo "=== OIDC Exec Test Script ==="
echo ""
echo "Environment Variables Received:"
echo "  OIDC_PROVIDER:      ${OIDC_PROVIDER:-<not set>}"
echo "  OIDC_ISSUER:        ${OIDC_ISSUER:-<not set>}"
echo "  OIDC_CLIENT_ID:     ${OIDC_CLIENT_ID:-<not set>}"
echo "  OIDC_SUBJECT:       ${OIDC_SUBJECT:-<not set>}"
echo "  OIDC_EMAIL:         ${OIDC_EMAIL:-<not set>}"
echo "  OIDC_NAME:          ${OIDC_NAME:-<not set>}"
echo "  OIDC_EXPIRES_AT:    ${OIDC_EXPIRES_AT:-<not set>}"
echo "  OIDC_EXPIRES_IN:    ${OIDC_EXPIRES_IN:-<not set>}"
echo "  OIDC_SCOPES:        ${OIDC_SCOPES:-<not set>}"
echo ""
echo "Token Lengths:"
echo "  OIDC_ACCESS_TOKEN:  ${#OIDC_ACCESS_TOKEN} chars"
echo "  OIDC_ID_TOKEN:      ${#OIDC_ID_TOKEN} chars"
echo "  OIDC_REFRESH_TOKEN: ${#OIDC_REFRESH_TOKEN} chars"
echo ""

# Read and display JSON payload from stdin
echo "JSON Payload from stdin:"
if [ -t 0 ]; then
    echo "  <no stdin data>"
else
    cat | jq -r 'to_entries | .[] | "  \(.key): \(.value | if type == "string" and length > 50 then "\(.[0:50])..." else . end)"' 2>/dev/null || echo "  <failed to parse JSON>"
fi

echo ""
echo "=== Test Complete ==="
