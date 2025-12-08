#!/bin/bash
# Installation script for keychaind
# This script installs the keychain daemon and sets up the systemd service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

echo -e "${GREEN}Installing keychain daemon...${NC}"

# Create keychain user and group
if ! id -u keychain &>/dev/null; then
    echo "Creating keychain user..."
    useradd --system --no-create-home --shell /bin/false keychain
else
    echo "User 'keychain' already exists"
fi

# Create required directories
echo "Creating directories..."
mkdir -p /etc/keychain /var/lib/keychain /var/run/keychain /var/log/keychain
chown keychain:keychain /var/lib/keychain /var/run/keychain /var/log/keychain
chmod 750 /var/lib/keychain /var/run/keychain /var/log/keychain

# Install binary
if [ -f "bin/keychaind" ]; then
    echo "Installing binary to /usr/bin/keychaind..."
    install -m 755 -o root -g root bin/keychaind /usr/bin/keychaind
elif [ -f "../bin/keychaind" ]; then
    echo "Installing binary to /usr/bin/keychaind..."
    install -m 755 -o root -g root ../bin/keychaind /usr/bin/keychaind
else
    echo -e "${RED}Error: keychaind binary not found${NC}"
    echo "Please build the binary first: go build -o bin/keychaind ./cmd/server"
    exit 1
fi

# Install configuration
if [ ! -f /etc/keychain/keychaind.yaml ]; then
    echo "Installing default configuration..."
    if [ -f "configs/keychaind.yaml.example" ]; then
        install -m 640 -o keychain -g keychain configs/keychaind.yaml.example /etc/keychain/keychaind.yaml
    elif [ -f "keychaind.yaml.example" ]; then
        install -m 640 -o keychain -g keychain keychaind.yaml.example /etc/keychain/keychaind.yaml
    else
        echo -e "${YELLOW}Warning: Example config not found, skipping config installation${NC}"
    fi

    # Update paths in config for production
    if [ -f /etc/keychain/keychaind.yaml ]; then
        sed -i 's|/tmp/keychain|/var/lib/keychain|g' /etc/keychain/keychaind.yaml
        sed -i 's|socket_path: "/tmp/keychain.sock"|socket_path: "/var/run/keychain/keychain.sock"|g' /etc/keychain/keychaind.yaml
    fi
else
    echo "Configuration file already exists at /etc/keychain/keychaind.yaml"
fi

# Install systemd service
echo "Installing systemd service..."
if [ -f "configs/keychaind.service" ]; then
    install -m 644 -o root -g root configs/keychaind.service /etc/systemd/system/keychaind.service
elif [ -f "keychaind.service" ]; then
    install -m 644 -o root -g root keychaind.service /etc/systemd/system/keychaind.service
else
    echo -e "${YELLOW}Warning: Service file not found${NC}"
fi

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review and customize the configuration: /etc/keychain/keychaind.yaml"
echo "  2. Enable the service: systemctl enable keychaind"
echo "  3. Start the service: systemctl start keychaind"
echo "  4. Check the status: systemctl status keychaind"
echo "  5. View logs: journalctl -u keychaind -f"
echo ""
echo "For more information, see: /etc/keychain/README.md"
