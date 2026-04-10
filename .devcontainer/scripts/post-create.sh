#!/bin/bash
# Post-create script for go-xkms devcontainer
# This script runs once after the container is created

set -e

echo "=== go-xkms Development Container Setup ==="

# All build tags for full integration testing
ALL_BUILD_TAGS="integration,frost,pkcs8,pkcs11,quantum,awskms,gcpkms,azurekv,vault,nitrokey,fido2,webauthn"

# Initialize SoftHSM token if not already initialized
# Token: xkms-test, SO PIN: 1234, User PIN: 1234, Slot: 0
if [ ! -f /var/lib/softhsm/tokens/.initialized ]; then
    echo "Initializing SoftHSM token..."
    sudo mkdir -p /var/lib/softhsm/tokens
    sudo chown -R $(whoami):$(whoami) /var/lib/softhsm
    softhsm2-util --init-token --slot 0 --label "xkms-test" --pin 1234 --so-pin 1234 || true
    touch /var/lib/softhsm/tokens/.initialized
    echo "SoftHSM token initialized: xkms-test"
fi

# Setup UHID device permissions for virtual FIDO2 testing
if [ -e /dev/uhid ]; then
    echo "Setting up UHID device permissions..."
    sudo chmod 666 /dev/uhid
    echo "UHID device permissions set"
else
    echo "Note: /dev/uhid not available (virtual FIDO2 tests will be skipped)"
fi

# Download Go dependencies
echo "Downloading Go dependencies..."
cd /workspace
go mod download

# Install additional Go tools if needed
echo "Installing Go tools..."
go install github.com/vektra/mockery/v2@latest 2>/dev/null || true

# Build CLI binary (xkmsctl - pure Go, no CGO required)
echo "Building xkmsctl CLI binary..."
mkdir -p build/bin
CGO_ENABLED=0 go build -buildvcs=false -o build/bin/xkmsctl ./cmd/xkmsctl
echo "CLI binary built: build/bin/xkmsctl"

# Build server binary with ALL build tags (requires CGO for PKCS#11, TPM2)
echo "Building xkmsd server binary with ALL build tags..."
CGO_ENABLED=1 go build -buildvcs=false -tags "${ALL_BUILD_TAGS}" -o build/bin/xkmsd ./cmd/xkmsd/
echo "Server binary built: build/bin/xkmsd"

# Generate protobuf files if proto compiler is available
if command -v protoc &> /dev/null; then
    echo "Checking protobuf files..."
    if [ -f "pkg/api/grpc/proto/xkmsv1/xkms.proto" ]; then
        make proto 2>/dev/null || true
    fi
fi

echo "=== Development environment ready! ==="
echo ""
echo "Build tags enabled: ${ALL_BUILD_TAGS}"
echo ""
echo "Available make targets:"
echo "  make build              - Build all binaries"
echo "  make test               - Run unit tests"
echo "  make integration-test   - Run all integration tests"
echo "  make integration-test-frost - Run FROST tests"
echo "  make integration-test-cli   - Run CLI integration tests"
echo ""
echo "Run 'make help' for all available targets"
