# go-xkms Deployment Guide

This directory contains service configuration files for deploying go-xkms as a system service on Linux.

## Prerequisites

1. Build the xkms server binary:
   ```bash
   make build-server
   ```

2. Copy the binary to the system path:
   ```bash
   sudo cp bin/xkmsd /usr/bin/
   sudo chmod 755 /usr/bin/xkmsd
   ```

3. Copy the CLI tool (optional, for administration):
   ```bash
   make build-cli
   sudo cp bin/xkmsctl /usr/bin/
   sudo chmod 755 /usr/bin/xkmsctl
   ```

## Configuration

Create the configuration directory and file:

```bash
sudo mkdir -p /etc/xkms
sudo cp configs/config.yaml /etc/xkms/config.yaml
sudo chmod 640 /etc/xkms/config.yaml
```

Edit `/etc/xkms/config.yaml` to match your environment. See the main documentation for configuration options.

## systemd (Debian, Ubuntu, RHEL, Fedora, Arch, etc.)

### Installation

1. Create the xkms user and directories:
   ```bash
   # Using systemd-sysusers (recommended)
   sudo cp deploy/systemd/xkms.sysusers /usr/lib/sysusers.d/xkms.conf
   sudo systemd-sysusers /usr/lib/sysusers.d/xkms.conf

   # Create directories using tmpfiles
   sudo cp deploy/systemd/xkms.tmpfiles /usr/lib/tmpfiles.d/xkms.conf
   sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/xkms.conf
   ```

   Or manually:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin -d /var/lib/xkms -c "xKMS Service" xkms
   sudo mkdir -p /var/lib/xkms/{keys,certs}
   sudo mkdir -p /var/log/xkms
   sudo chown -R xkms:xkms /var/lib/xkms /var/log/xkms
   sudo chmod 750 /var/lib/xkms /var/log/xkms
   sudo chmod 700 /var/lib/xkms/keys
   ```

2. Install the service file:
   ```bash
   sudo cp deploy/systemd/xkms.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. (Optional) Create environment file for additional settings:
   ```bash
   sudo touch /etc/xkms/environment
   sudo chmod 640 /etc/xkms/environment
   sudo chown root:xkms /etc/xkms/environment
   ```

### Usage

```bash
# Enable service to start on boot
sudo systemctl enable xkms

# Start the service
sudo systemctl start xkms

# Check status
sudo systemctl status xkms

# View logs
sudo journalctl -u xkms -f

# Reload configuration (sends HUP signal)
sudo systemctl reload xkms

# Stop the service
sudo systemctl stop xkms
```

## OpenRC (Alpine Linux, Gentoo)

### Installation

1. Create the xkms user and directories:
   ```bash
   # Create user
   sudo adduser -S -D -H -h /var/lib/xkms -s /sbin/nologin -G xkms xkms
   sudo addgroup -S xkms

   # Create directories
   sudo mkdir -p /var/lib/xkms/{keys,certs}
   sudo mkdir -p /var/log/xkms
   sudo mkdir -p /run/xkms
   sudo chown -R xkms:xkms /var/lib/xkms /var/log/xkms /run/xkms
   sudo chmod 750 /var/lib/xkms /var/log/xkms
   sudo chmod 700 /var/lib/xkms/keys
   ```

2. Install the init script:
   ```bash
   sudo cp deploy/openrc/xkms /etc/init.d/
   sudo chmod 755 /etc/init.d/xkms
   ```

3. Install the configuration file:
   ```bash
   sudo cp deploy/openrc/xkms.confd /etc/conf.d/xkms
   ```

### Usage

```bash
# Add to default runlevel
sudo rc-update add xkms default

# Start the service
sudo rc-service xkms start

# Check status
sudo rc-service xkms status

# View logs
sudo tail -f /var/log/xkms/xkms.log

# Reload configuration
sudo rc-service xkms reload

# Stop the service
sudo rc-service xkms stop
```

## First-Time Setup

After the service is running, you need to initialize the admin user with a FIDO2 security key:

1. Ensure you have a FIDO2-compatible security key (YubiKey 5, SoloKey, etc.)

2. Run the admin creation command:
   ```bash
   sudo -u xkms xkmsctl admin create --username admin
   ```

3. Follow the prompts to register your security key.

See the [Admin Guide](../docs/admin.md) for more details on user management.

## Security Considerations

- The xkms service runs as a dedicated non-privileged user
- Private keys are stored with mode 0700 (owner read/write only)
- The service is hardened with systemd security features:
  - NoNewPrivileges
  - ProtectSystem=strict
  - PrivateTmp
  - RestrictAddressFamilies
  - SystemCallFilter

### TPM Access

If using TPM2 backend, ensure the xkms user has access to TPM devices:

```bash
# Add xkms to tss group (common on most distros)
sudo usermod -a -G tss xkms

# Or create udev rule for direct access
echo 'SUBSYSTEM=="tpm", MODE="0660", GROUP="xkms"' | sudo tee /etc/udev/rules.d/99-xkms-tpm.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### PKCS#11 / Smart Card Access

If using PKCS#11 backend with smart cards:

```bash
# Ensure pcscd is running
sudo systemctl enable pcscd
sudo systemctl start pcscd

# Add xkms user to appropriate group
sudo usermod -a -G pcscd xkms  # or 'scard' on some systems
```

## Troubleshooting

### Service fails to start

1. Check the logs:
   ```bash
   # systemd
   sudo journalctl -u xkms -e

   # OpenRC
   sudo cat /var/log/xkms/xkms.log
   ```

2. Verify configuration:
   ```bash
   sudo -u xkms xkmsd -config /etc/xkms/config.yaml -version
   ```

3. Check file permissions:
   ```bash
   ls -la /etc/xkms/
   ls -la /var/lib/xkms/
   ```

### Permission denied errors

Ensure the xkms user owns all required directories:
```bash
sudo chown -R xkms:xkms /var/lib/xkms /var/log/xkms
```

### TPM not accessible

Check TPM device permissions:
```bash
ls -la /dev/tpm*
groups xkms
```
