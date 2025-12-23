#!/bin/bash
# Post-create script for go-keychain devcontainer
# This script runs once after the container is created

set -e

echo "=== go-keychain Development Container Setup ==="

# Initialize SoftHSM token if not already initialized
if [ ! -f /var/lib/softhsm/tokens/.initialized ]; then
    echo "Initializing SoftHSM token..."
    sudo mkdir -p /var/lib/softhsm/tokens
    sudo chown -R $(whoami):$(whoami) /var/lib/softhsm
    softhsm2-util --init-token --slot 0 --label "DevToken" --pin 1234 --so-pin 12345678 || true
    touch /var/lib/softhsm/tokens/.initialized
    echo "SoftHSM token initialized"
fi

# Download Go dependencies
echo "Downloading Go dependencies..."
cd /workspace
go mod download

# Install additional Go tools if needed
echo "Installing Go tools..."
go install github.com/vektra/mockery/v2@latest 2>/dev/null || true

# Build the CLI binary
echo "Building CLI binary..."
make build-cli 2>/dev/null || go build -o build/bin/keychain ./cmd/cli/main.go

# Generate protobuf files if proto compiler is available
if command -v protoc &> /dev/null; then
    echo "Checking protobuf files..."
    if [ -f "api/proto/keychainv1/keychain.proto" ]; then
        make proto 2>/dev/null || true
    fi
fi

echo "=== Development environment ready! ==="
echo ""
echo "Available make targets:"
echo "  make build          - Build all binaries"
echo "  make test           - Run unit tests"
echo "  make integration-test - Run all integration tests"
echo "  make integration-test-frost - Run FROST tests"
echo "  make integration-test-cli - Run CLI integration tests"
echo ""
echo "Run 'make help' for all available targets"
