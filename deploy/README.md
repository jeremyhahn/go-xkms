# go-keychain Deployment Guide

This directory contains service configuration files for deploying go-keychain as a system service on Linux.

## Prerequisites

1. Build the keychain server binary:
   ```bash
   make build-server
   ```

2. Copy the binary to the system path:
   ```bash
   sudo cp bin/keychaind /usr/bin/
   sudo chmod 755 /usr/bin/keychaind
   ```

3. Copy the CLI tool (optional, for administration):
   ```bash
   make build-cli
   sudo cp bin/keychain /usr/bin/
   sudo chmod 755 /usr/bin/keychain
   ```

## Configuration

Create the configuration directory and file:

```bash
sudo mkdir -p /etc/keychain
sudo cp configs/config.yaml /etc/keychain/config.yaml
sudo chmod 640 /etc/keychain/config.yaml
```

Edit `/etc/keychain/config.yaml` to match your environment. See the main documentation for configuration options.

## systemd (Debian, Ubuntu, RHEL, Fedora, Arch, etc.)

### Installation

1. Create the keychain user and directories:
   ```bash
   # Using systemd-sysusers (recommended)
   sudo cp deploy/systemd/keychain.sysusers /usr/lib/sysusers.d/keychain.conf
   sudo systemd-sysusers /usr/lib/sysusers.d/keychain.conf

   # Create directories using tmpfiles
   sudo cp deploy/systemd/keychain.tmpfiles /usr/lib/tmpfiles.d/keychain.conf
   sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/keychain.conf
   ```

   Or manually:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin -d /var/lib/keychain -c "Keychain Service" keychain
   sudo mkdir -p /var/lib/keychain/{keys,certs}
   sudo mkdir -p /var/log/keychain
   sudo chown -R keychain:keychain /var/lib/keychain /var/log/keychain
   sudo chmod 750 /var/lib/keychain /var/log/keychain
   sudo chmod 700 /var/lib/keychain/keys
   ```

2. Install the service file:
   ```bash
   sudo cp deploy/systemd/keychain.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. (Optional) Create environment file for additional settings:
   ```bash
   sudo touch /etc/keychain/environment
   sudo chmod 640 /etc/keychain/environment
   sudo chown root:keychain /etc/keychain/environment
   ```

### Usage

```bash
# Enable service to start on boot
sudo systemctl enable keychain

# Start the service
sudo systemctl start keychain

# Check status
sudo systemctl status keychain

# View logs
sudo journalctl -u keychain -f

# Reload configuration (sends HUP signal)
sudo systemctl reload keychain

# Stop the service
sudo systemctl stop keychain
```

## OpenRC (Alpine Linux, Gentoo)

### Installation

1. Create the keychain user and directories:
   ```bash
   # Create user
   sudo adduser -S -D -H -h /var/lib/keychain -s /sbin/nologin -G keychain keychain
   sudo addgroup -S keychain

   # Create directories
   sudo mkdir -p /var/lib/keychain/{keys,certs}
   sudo mkdir -p /var/log/keychain
   sudo mkdir -p /run/keychain
   sudo chown -R keychain:keychain /var/lib/keychain /var/log/keychain /run/keychain
   sudo chmod 750 /var/lib/keychain /var/log/keychain
   sudo chmod 700 /var/lib/keychain/keys
   ```

2. Install the init script:
   ```bash
   sudo cp deploy/openrc/keychain /etc/init.d/
   sudo chmod 755 /etc/init.d/keychain
   ```

3. Install the configuration file:
   ```bash
   sudo cp deploy/openrc/keychain.confd /etc/conf.d/keychain
   ```

### Usage

```bash
# Add to default runlevel
sudo rc-update add keychain default

# Start the service
sudo rc-service keychain start

# Check status
sudo rc-service keychain status

# View logs
sudo tail -f /var/log/keychain/keychain.log

# Reload configuration
sudo rc-service keychain reload

# Stop the service
sudo rc-service keychain stop
```

## First-Time Setup

After the service is running, you need to initialize the admin user with a FIDO2 security key:

1. Ensure you have a FIDO2-compatible security key (YubiKey 5, SoloKey, etc.)

2. Run the admin creation command:
   ```bash
   sudo -u keychain keychain admin create --username admin
   ```

3. Follow the prompts to register your security key.

See the [Admin Guide](../docs/admin.md) for more details on user management.

## Security Considerations

- The keychain service runs as a dedicated non-privileged user
- Private keys are stored with mode 0700 (owner read/write only)
- The service is hardened with systemd security features:
  - NoNewPrivileges
  - ProtectSystem=strict
  - PrivateTmp
  - RestrictAddressFamilies
  - SystemCallFilter

### TPM Access

If using TPM2 backend, ensure the keychain user has access to TPM devices:

```bash
# Add keychain to tss group (common on most distros)
sudo usermod -a -G tss keychain

# Or create udev rule for direct access
echo 'SUBSYSTEM=="tpm", MODE="0660", GROUP="keychain"' | sudo tee /etc/udev/rules.d/99-keychain-tpm.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### PKCS#11 / Smart Card Access

If using PKCS#11 backend with smart cards:

```bash
# Ensure pcscd is running
sudo systemctl enable pcscd
sudo systemctl start pcscd

# Add keychain user to appropriate group
sudo usermod -a -G pcscd keychain  # or 'scard' on some systems
```

## Troubleshooting

### Service fails to start

1. Check the logs:
   ```bash
   # systemd
   sudo journalctl -u keychain -e

   # OpenRC
   sudo cat /var/log/keychain/keychain.log
   ```

2. Verify configuration:
   ```bash
   sudo -u keychain keychaind -config /etc/keychain/config.yaml -version
   ```

3. Check file permissions:
   ```bash
   ls -la /etc/keychain/
   ls -la /var/lib/keychain/
   ```

### Permission denied errors

Ensure the keychain user owns all required directories:
```bash
sudo chown -R keychain:keychain /var/lib/keychain /var/log/keychain
```

### TPM not accessible

Check TPM device permissions:
```bash
ls -la /dev/tpm*
groups keychain
```
