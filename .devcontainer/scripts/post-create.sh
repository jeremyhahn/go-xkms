#!/bin/bash
# Post-create script for go-keychain devcontainer
# This script runs once after the container is created

set -e

echo "=== go-keychain Development Container Setup ==="

# All build tags for full integration testing
ALL_BUILD_TAGS="integration,frost,pkcs8,pkcs11,quantum,awskms,gcpkms,azurekv,vault,tpm_simulator,yubikey,nitrokey,canokey,fido2,webauthn"

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

# Build CLI binary with ALL build tags
echo "Building CLI binary with ALL build tags..."
if [ -f Makefile ] && grep -q "build-cli" Makefile; then
    make build-cli WITH_PKCS8=1 WITH_PKCS11=1 WITH_FROST=1 WITH_QUANTUM=1 WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1 WITH_VAULT=1 WITH_TPM_SIMULATOR=1 2>/dev/null || \
    CGO_ENABLED=1 go build -tags "${ALL_BUILD_TAGS}" -o build/bin/keychain ./cmd/cli/main.go
else
    CGO_ENABLED=1 go build -tags "${ALL_BUILD_TAGS}" -o build/bin/keychain ./cmd/cli/main.go
fi

# Build server binary with ALL build tags
echo "Building server binary with ALL build tags..."
if [ -f Makefile ] && grep -q "build-server" Makefile; then
    make build-server WITH_PKCS8=1 WITH_PKCS11=1 WITH_FROST=1 WITH_QUANTUM=1 WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1 WITH_VAULT=1 WITH_TPM_SIMULATOR=1 2>/dev/null || \
    CGO_ENABLED=1 go build -tags "${ALL_BUILD_TAGS}" -o build/bin/keychaind ./cmd/server/main.go
else
    CGO_ENABLED=1 go build -tags "${ALL_BUILD_TAGS}" -o build/bin/keychaind ./cmd/server/main.go
fi

# Generate protobuf files if proto compiler is available
if command -v protoc &> /dev/null; then
    echo "Checking protobuf files..."
    if [ -f "api/proto/keychainv1/keychain.proto" ]; then
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
