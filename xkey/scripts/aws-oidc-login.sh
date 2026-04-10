#!/bin/bash
# aws-oidc-login.sh - Exchange OIDC token for AWS credentials
#
# This script is called by xkey after OIDC login and exchanges the
# ID token for temporary AWS credentials using STS AssumeRoleWithWebIdentity.
#
# Usage:
#   xkey oidc login --issuer https://your-idp.com --client-id ID --exec ./aws-oidc-login.sh
#
# Required environment variables (set by xkey):
#   OIDC_ID_TOKEN      - The OIDC ID token to exchange
#   OIDC_EMAIL         - User's email (used for session name)
#
# Required configuration (set before running):
#   AWS_ROLE_ARN       - The IAM role ARN to assume
#   AWS_REGION         - (optional) AWS region, defaults to us-east-1
#
# The script writes credentials to ~/.aws/credentials under the [oidc] profile.

set -euo pipefail

# Configuration - set these or pass via environment
# Use ${VAR:-} to provide default empty value for unset variables (for -u compatibility)
OIDC_ID_TOKEN="${OIDC_ID_TOKEN:-}"
OIDC_EMAIL="${OIDC_EMAIL:-}"
AWS_ROLE_ARN="${AWS_ROLE_ARN:-}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE_NAME="${AWS_PROFILE_NAME:-oidc}"
SESSION_DURATION="${SESSION_DURATION:-3600}"

# Validate required inputs
if [[ -z "$OIDC_ID_TOKEN" ]]; then
    echo "Error: OIDC_ID_TOKEN not set. Run this script via 'xkey oidc login --exec'" >&2
    exit 1
fi

if [[ -z "$AWS_ROLE_ARN" ]]; then
    echo "Error: AWS_ROLE_ARN environment variable is required" >&2
    echo "Example: export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/OIDCRole" >&2
    exit 1
fi

# Generate session name from email or use default
SESSION_NAME="${OIDC_EMAIL:-xkey-session}"
# Sanitize session name (AWS allows alphanumeric, =,.@- only, max 64 chars)
SESSION_NAME=$(echo "$SESSION_NAME" | tr -cd '[:alnum:]=,.@-' | cut -c1-64)
if [[ -z "$SESSION_NAME" ]]; then
    SESSION_NAME="xkey-session"
fi

echo "Exchanging OIDC token for AWS credentials..."
echo "  Role ARN: $AWS_ROLE_ARN"
echo "  Session:  $SESSION_NAME"
echo "  Region:   $AWS_REGION"

# Call STS AssumeRoleWithWebIdentity
RESPONSE=$(aws sts assume-role-with-web-identity \
    --role-arn "$AWS_ROLE_ARN" \
    --role-session-name "$SESSION_NAME" \
    --web-identity-token "$OIDC_ID_TOKEN" \
    --duration-seconds "$SESSION_DURATION" \
    --region "$AWS_REGION" \
    --output json 2>&1) || {
    echo "Error: AWS STS call failed" >&2
    echo "$RESPONSE" >&2
    exit 1
}

# Extract credentials
ACCESS_KEY_ID=$(echo "$RESPONSE" | jq -r '.Credentials.AccessKeyId')
SECRET_ACCESS_KEY=$(echo "$RESPONSE" | jq -r '.Credentials.SecretAccessKey')
SESSION_TOKEN=$(echo "$RESPONSE" | jq -r '.Credentials.SessionToken')
EXPIRATION=$(echo "$RESPONSE" | jq -r '.Credentials.Expiration')

if [[ -z "$ACCESS_KEY_ID" || "$ACCESS_KEY_ID" == "null" ]]; then
    echo "Error: Failed to parse credentials from STS response" >&2
    exit 1
fi

# Ensure ~/.aws directory exists
mkdir -p ~/.aws
chmod 700 ~/.aws

# Write to AWS credentials file
AWS_CREDENTIALS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"

# Create or update the profile in credentials file
# Use a temp file for atomic write
TEMP_FILE=$(mktemp)
trap "rm -f $TEMP_FILE" EXIT

if [[ -f "$AWS_CREDENTIALS_FILE" ]]; then
    # Remove existing profile section if present
    awk -v profile="[$AWS_PROFILE_NAME]" '
        BEGIN { skip=0 }
        /^\[/ { skip=0 }
        $0 == profile { skip=1; next }
        skip { next }
        { print }
    ' "$AWS_CREDENTIALS_FILE" > "$TEMP_FILE"
else
    touch "$TEMP_FILE"
fi

# Append new profile
cat >> "$TEMP_FILE" << EOF
[$AWS_PROFILE_NAME]
aws_access_key_id = $ACCESS_KEY_ID
aws_secret_access_key = $SECRET_ACCESS_KEY
aws_session_token = $SESSION_TOKEN
# Expires: $EXPIRATION
EOF

# Move temp file to credentials file
mv "$TEMP_FILE" "$AWS_CREDENTIALS_FILE"
chmod 600 "$AWS_CREDENTIALS_FILE"

echo ""
echo "AWS credentials saved to $AWS_CREDENTIALS_FILE [$AWS_PROFILE_NAME]"
echo "  Expires: $EXPIRATION"
echo ""
echo "Use with: aws --profile $AWS_PROFILE_NAME <command>"
echo "Or:       export AWS_PROFILE=$AWS_PROFILE_NAME"
