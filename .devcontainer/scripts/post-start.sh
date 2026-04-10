#!/bin/bash
# Post-start script for go-xkms devcontainer
# This script runs every time the container starts

set -e

echo "=== Starting go-xkms Development Environment ==="

# All build tags for reference
ALL_BUILD_TAGS="integration,frost,pkcs8,pkcs11,quantum,awskms,gcpkms,azurekv,vault,nitrokey,fido2,webauthn"

# Ensure SoftHSM directories have correct permissions
sudo chown -R $(whoami):$(whoami) /var/lib/softhsm 2>/dev/null || true

# Setup UHID device for virtual FIDO2 testing
# UHID requires privileged mode and Linux kernel support
if [ -e /dev/uhid ]; then
    sudo chmod 666 /dev/uhid
    echo "✓ UHID device available and permissions set"
elif [ -c /dev/uhid ] 2>/dev/null || sudo test -c /dev/uhid 2>/dev/null; then
    sudo chmod 666 /dev/uhid
    echo "✓ UHID device permissions set"
else
    # Try to create UHID device node (requires privileged mode and UHID module loaded)
    # UHID major number is 10 (misc), minor is typically 239
    if sudo modprobe uhid 2>/dev/null && sudo mknod -m 666 /dev/uhid c 10 239 2>/dev/null; then
        echo "✓ UHID device created successfully"
    else
        echo "⚠ /dev/uhid not available (virtual FIDO2 tests will be skipped)"
        echo "  Note: UHID requires Linux kernel with CONFIG_UHID=y and privileged mode"
    fi
fi

# Start udevd for proper device enumeration (required for fido2-token)
# This is needed for libfido2 to properly enumerate FIDO2 devices
if command -v udevd &> /dev/null; then
    if ! pgrep -x udevd > /dev/null; then
        echo "Starting udevd for device enumeration..."
        sudo udevd --daemon 2>/dev/null || true
        # Wait for udevd to start
        sleep 1
        # Trigger udev rules for existing devices
        sudo udevadm trigger 2>/dev/null || true
        sudo udevadm settle 2>/dev/null || true
        echo "✓ udevd started for device enumeration"
    else
        echo "✓ udevd already running"
    fi
else
    echo "⚠ udevd not available (fido2-token enumeration may not work)"
fi

# Set permissions on hidraw devices for FIDO2 access
for hidraw in /dev/hidraw*; do
    if [ -c "$hidraw" ]; then
        sudo chmod 666 "$hidraw" 2>/dev/null || true
    fi
done

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

# Check XKMS Server
MAX_WAIT=30
WAITED=0
echo "Checking xkms-server availability..."
while [ $WAITED -lt $MAX_WAIT ]; do
    if nc -z xkms-server 8443 2>/dev/null; then
        echo "✓ XKMS server available at xkms-server:8443"
        break
    fi
    if [ $WAITED -eq 0 ]; then
        echo "  Waiting for xkms-server to become available..."
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "⚠ XKMS server not available after ${MAX_WAIT}s (server integration tests may fail)"
    echo "  Check 'docker compose logs xkms-server' for details"
fi

# Verify all server protocols
if nc -z xkms-server 8443 2>/dev/null; then
    echo ""
    echo "Checking server protocols..."

    # REST API
    if nc -z xkms-server 8443 2>/dev/null; then
        echo "✓ REST API (port 8443)"
    else
        echo "⚠ REST API not available"
    fi

    # gRPC
    if nc -z xkms-server 9443 2>/dev/null; then
        echo "✓ gRPC (port 9443)"
    else
        echo "⚠ gRPC not available"
    fi

    # QUIC
    if nc -z xkms-server 8444 2>/dev/null; then
        echo "✓ QUIC (port 8444)"
    else
        echo "⚠ QUIC not available"
    fi

    # MCP
    if nc -z xkms-server 9444 2>/dev/null; then
        echo "✓ MCP (port 9444)"
    else
        echo "⚠ MCP not available"
    fi

    # Metrics
    if nc -z xkms-server 9090 2>/dev/null; then
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

# Build binaries for integration testing
echo ""
echo "Building binaries for integration testing..."
cd /workspace

# Build xkey binary (used by LUKS integration tests)
if [ ! -f build/bin/xkey ] || [ "$(find xkey -name '*.go' -newer build/bin/xkey 2>/dev/null | head -1)" ]; then
    echo "  Building xkey..."
    mkdir -p build/bin
    cd xkey && GOOS=linux CGO_ENABLED=0 go build -buildvcs=false -o ../build/bin/xkey ./cmd/xkey
    cd /workspace
    echo "✓ xkey binary built: /workspace/build/bin/xkey"
else
    echo "✓ xkey binary up-to-date: /workspace/build/bin/xkey"
fi

# Build xkmsctl if not already built
if [ ! -f build/bin/xkmsctl ]; then
    echo "  Building xkmsctl..."
    mkdir -p build/bin
    CGO_ENABLED=0 go build -buildvcs=false -o build/bin/xkmsctl ./cmd/xkmsctl
    echo "✓ xkmsctl binary built: /workspace/build/bin/xkmsctl"
else
    echo "✓ xkmsctl binary present: /workspace/build/bin/xkmsctl"
fi

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
echo "  KEYSTORE_REST_URL=http://xkms-server:8443"
echo "  KEYSTORE_GRPC_ADDR=xkms-server:9443"
echo "  KEYSTORE_QUIC_URL=https://xkms-server:8444"
echo "  KEYSTORE_MCP_ADDR=xkms-server:9444"
echo ""
