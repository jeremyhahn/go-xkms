#!/bin/bash
# Post-start script for go-keychain devcontainer
# This script runs every time the container starts

set -e

echo "=== Starting go-keychain Development Environment ==="

# Ensure SoftHSM directories have correct permissions
sudo chown -R $(whoami):$(whoami) /var/lib/softhsm 2>/dev/null || true

# Check if services are available
echo "Checking service availability..."

# Check SWTPM
if nc -z swtpm 2321 2>/dev/null; then
    echo "✓ SWTPM TPM simulator available at swtpm:2321"
else
    echo "⚠ SWTPM not available (some TPM tests will be skipped)"
fi

# Check SoftHSM
if [ -f "/usr/lib/softhsm/libsofthsm2.so" ]; then
    echo "✓ SoftHSM library available"
else
    echo "⚠ SoftHSM library not found"
fi

# Set up Go environment
export GOPATH=/go
export PATH=/go/bin:/usr/local/go/bin:$PATH

# Verify Go installation
echo ""
echo "Go version: $(go version)"
echo "GOPATH: $GOPATH"

# Display quick start info
echo ""
echo "=== Development Environment Ready ==="
echo ""
echo "Quick start:"
echo "  make build    - Build all binaries"
echo "  make test     - Run unit tests"
echo "  make help     - Show all targets"
echo ""
echo "To start the keychain server for integration tests:"
echo "  docker compose --profile server up -d keychain-server"
echo ""
