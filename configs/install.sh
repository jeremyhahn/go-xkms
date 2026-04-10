#!/bin/bash
# Installation script for xkmsd
# This script installs the xkms daemon and sets up the systemd service

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

echo -e "${GREEN}Installing xkms daemon...${NC}"

# Create xkms user and group
if ! id -u xkms &>/dev/null; then
    echo "Creating xkms user..."
    useradd --system --no-create-home --shell /bin/false xkms
else
    echo "User 'xkms' already exists"
fi

# Create required directories
echo "Creating directories..."
mkdir -p /etc/xkms /var/lib/xkms /var/run/xkms /var/log/xkms
chown xkms:xkms /var/lib/xkms /var/run/xkms /var/log/xkms
chmod 750 /var/lib/xkms /var/run/xkms /var/log/xkms

# Install binary
if [ -f "bin/xkmsd" ]; then
    echo "Installing binary to /usr/bin/xkmsd..."
    install -m 755 -o root -g root bin/xkmsd /usr/bin/xkmsd
elif [ -f "../bin/xkmsd" ]; then
    echo "Installing binary to /usr/bin/xkmsd..."
    install -m 755 -o root -g root ../bin/xkmsd /usr/bin/xkmsd
else
    echo -e "${RED}Error: xkmsd binary not found${NC}"
    echo "Please build the binary first: go build -o bin/xkmsd ./cmd/server"
    exit 1
fi

# Install configuration
if [ ! -f /etc/xkms/xkmsd.yaml ]; then
    echo "Installing default configuration..."
    if [ -f "configs/xkmsd.yaml.example" ]; then
        install -m 640 -o xkms -g xkms configs/xkmsd.yaml.example /etc/xkms/xkmsd.yaml
    elif [ -f "xkmsd.yaml.example" ]; then
        install -m 640 -o xkms -g xkms xkmsd.yaml.example /etc/xkms/xkmsd.yaml
    else
        echo -e "${YELLOW}Warning: Example config not found, skipping config installation${NC}"
    fi

    # Update paths in config for production
    if [ -f /etc/xkms/xkmsd.yaml ]; then
        sed -i 's|/tmp/xkms|/var/lib/xkms|g' /etc/xkms/xkmsd.yaml
        sed -i 's|socket_path: "/tmp/xkms.sock"|socket_path: "/var/run/xkms/xkms.sock"|g' /etc/xkms/xkmsd.yaml
    fi
else
    echo "Configuration file already exists at /etc/xkms/xkmsd.yaml"
fi

# Install systemd service
echo "Installing systemd service..."
if [ -f "configs/xkmsd.service" ]; then
    install -m 644 -o root -g root configs/xkmsd.service /etc/systemd/system/xkmsd.service
elif [ -f "xkmsd.service" ]; then
    install -m 644 -o root -g root xkmsd.service /etc/systemd/system/xkmsd.service
else
    echo -e "${YELLOW}Warning: Service file not found${NC}"
fi

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review and customize the configuration: /etc/xkms/xkmsd.yaml"
echo "  2. Enable the service: systemctl enable xkmsd"
echo "  3. Start the service: systemctl start xkmsd"
echo "  4. Check the status: systemctl status xkmsd"
echo "  5. View logs: journalctl -u xkmsd -f"
echo ""
echo "For more information, see: /etc/xkms/README.md"
