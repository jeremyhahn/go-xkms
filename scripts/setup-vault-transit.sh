#!/bin/bash
# Setup script for Vault Transit engine

set -e

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
MAX_RETRIES=30
RETRY_DELAY=1

echo "Waiting for Vault to be ready..."

# Wait for Vault to be available
for i in $(seq 1 $MAX_RETRIES); do
    if curl -s -f "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; then
        echo "✓ Vault is ready"
        break
    fi
    if [ $i -eq $MAX_RETRIES ]; then
        echo "✗ Vault did not become ready in time"
        exit 1
    fi
    echo "Waiting for Vault... ($i/$MAX_RETRIES)"
    sleep $RETRY_DELAY
done

# Enable Transit secrets engine
echo "Enabling Transit secrets engine..."

# Check if Transit is already enabled
SECRETS_LIST=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/sys/mounts")
if echo "$SECRETS_LIST" | grep -q '"transit/"'; then
    echo "✓ Transit secrets engine is already enabled"
else
    # Enable Transit engine
    curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"type":"transit","description":"Transit engine for key management"}' \
        "$VAULT_ADDR/v1/sys/mounts/transit" >/dev/null

    if [ $? -eq 0 ]; then
        echo "✓ Transit secrets engine enabled"
    else
        echo "✗ Failed to enable Transit secrets engine"
        exit 1
    fi
fi

echo "✓ Vault Transit engine is ready for testing"
