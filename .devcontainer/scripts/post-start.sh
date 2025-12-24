#!/bin/bash
# Post-start script for go-keychain devcontainer
# This script runs every time the container starts

set -e

echo "=== Starting go-keychain Development Environment ==="

# All build tags for reference
ALL_BUILD_TAGS="integration,frost,pkcs8,pkcs11,quantum,awskms,gcpkms,azurekv,vault,tpm_simulator,yubikey,nitrokey,canokey,fido2,webauthn"

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
elif [ -f "/usr/local/lib/softhsm/libsofthsm2.so" ]; then
    echo "✓ SoftHSM library available at /usr/local/lib/softhsm/libsofthsm2.so"
else
    echo "⚠ SoftHSM library not found"
fi

# Check OpenSC (for CanoKey PIV)
if [ -f "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so" ]; then
    echo "✓ OpenSC PKCS#11 library available (CanoKey PIV support)"
elif [ -f "/usr/lib/opensc-pkcs11.so" ]; then
    echo "✓ OpenSC PKCS#11 library available"
else
    echo "⚠ OpenSC PKCS#11 library not found (CanoKey PIV tests may be skipped)"
fi

# Check CanoKey QEMU virtual device
echo ""
echo "Checking CanoKey QEMU..."
MAX_CANOKEY_WAIT=30
CANOKEY_WAITED=0
while [ $CANOKEY_WAITED -lt $MAX_CANOKEY_WAIT ]; do
    if [ -S "/var/lib/canokey/canokey.sock" ]; then
        echo "✓ CanoKey QEMU socket available at /var/lib/canokey/canokey.sock"
        echo "  CANOKEY_QEMU=${CANOKEY_QEMU:-/var/lib/canokey/canokey.sock}"
        echo "  FIDO2_DEVICE_PATH=${FIDO2_DEVICE_PATH:-/var/lib/canokey/canokey.sock}"
        break
    fi
    if [ $CANOKEY_WAITED -eq 0 ]; then
        echo "  Waiting for CanoKey QEMU to become available..."
    fi
    sleep 1
    CANOKEY_WAITED=$((CANOKEY_WAITED + 1))
done

if [ $CANOKEY_WAITED -ge $MAX_CANOKEY_WAIT ]; then
    echo "⚠ CanoKey QEMU socket not available after ${MAX_CANOKEY_WAIT}s"
    echo "  FIDO2 and CanoKey PIV tests may be skipped"
    echo "  Check 'docker compose logs canokey-qemu' for details"
fi

# Check FIDO2/libfido2
if command -v fido2-token &> /dev/null; then
    echo "✓ libfido2 tools available (fido2-token)"
    # Try to list devices
    FIDO2_DEVICES=$(fido2-token -L 2>/dev/null || echo "")
    if [ -n "$FIDO2_DEVICES" ]; then
        echo "  FIDO2 devices found:"
        echo "$FIDO2_DEVICES" | sed 's/^/    /'
    fi
else
    echo "⚠ libfido2 tools not installed (install with: apt-get install fido2-tools)"
fi

# Check Keychain Server
MAX_WAIT=30
WAITED=0
echo "Checking keychain-server availability..."
while [ $WAITED -lt $MAX_WAIT ]; do
    if nc -z keychain-server 8443 2>/dev/null; then
        echo "✓ Keychain server available at keychain-server:8443"
        break
    fi
    if [ $WAITED -eq 0 ]; then
        echo "  Waiting for keychain-server to become available..."
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "⚠ Keychain server not available after ${MAX_WAIT}s (server integration tests may fail)"
    echo "  Check 'docker compose logs keychain-server' for details"
fi

# Verify all server protocols
if nc -z keychain-server 8443 2>/dev/null; then
    echo ""
    echo "Checking server protocols..."

    # REST API
    if nc -z keychain-server 8443 2>/dev/null; then
        echo "✓ REST API (port 8443)"
    else
        echo "⚠ REST API not available"
    fi

    # gRPC
    if nc -z keychain-server 9443 2>/dev/null; then
        echo "✓ gRPC (port 9443)"
    else
        echo "⚠ gRPC not available"
    fi

    # QUIC
    if nc -z keychain-server 8444 2>/dev/null; then
        echo "✓ QUIC (port 8444)"
    else
        echo "⚠ QUIC not available"
    fi

    # MCP
    if nc -z keychain-server 9444 2>/dev/null; then
        echo "✓ MCP (port 9444)"
    else
        echo "⚠ MCP not available"
    fi

    # Metrics
    if nc -z keychain-server 9090 2>/dev/null; then
        echo "✓ Metrics (port 9090)"
    else
        echo "⚠ Metrics not available"
    fi
fi

# Set up Go environment
export GOPATH=/go
export PATH=/go/bin:/usr/local/go/bin:$PATH

# Verify Go installation
echo ""
echo "Go version: $(go version)"
echo "GOPATH: $GOPATH"
echo "Build tags: ${ALL_BUILD_TAGS}"

# Display quick start info
echo ""
echo "=== Development Environment Ready ==="
echo ""
echo "Quick start:"
echo "  make build              - Build all binaries with all tags"
echo "  make test               - Run unit tests"
echo "  make integration-test   - Run integration tests"
echo "  make help               - Show all targets"
echo ""
echo "Integration test endpoints:"
echo "  KEYSTORE_REST_URL=http://keychain-server:8443"
echo "  KEYSTORE_GRPC_ADDR=keychain-server:9443"
echo "  KEYSTORE_QUIC_URL=https://keychain-server:8444"
echo "  KEYSTORE_MCP_ADDR=keychain-server:9444"
echo ""
