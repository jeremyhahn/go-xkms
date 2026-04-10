# fido2key Configuration Guide

This guide covers all configuration options for fido2key with detailed explanations and best practices.

## Configuration Methods

fido2key is configured via command-line flags. All options have sensible defaults for quick startup.

## Storage Configuration

### Storage Type

The `--storage` flag selects the credential storage backend.

| Value | Description |
|-------|-------------|
| `memory` | In-memory storage (volatile, credentials lost on exit) |
| `file` | File-based storage (persistent across restarts) |

**Memory Storage** (Default):
```bash
sudo fido2key --storage memory
```

Best for:
- Automated testing
- Development environments
- Ephemeral credentials

**File Storage**:
```bash
sudo fido2key --storage file --storage-path /var/lib/fido2key
```

Best for:
- Production deployments
- Long-running services
- Credential persistence requirements

### Storage Path

When using file storage, `--storage-path` specifies the directory for credential data.

```bash
sudo fido2key --storage file --storage-path /var/lib/fido2key
```

The directory is created if it does not exist. Ensure the fido2key process has write permissions.

**Directory Structure**:
```
/var/lib/fido2key/
  fido2key/
    credentials/     # Stored credentials
    state.json       # Authenticator state (counters, PIN hash)
```

## Device Configuration

### Device Name

The `--name` flag sets the device name reported to the operating system.

```bash
sudo fido2key --name "My Test FIDO2 Key"
```

Default: `Virtual FIDO2 Key (go-keychain)`

This name appears in:
- `lsusb` output
- Browser WebAuthn prompts
- System device managers

### Serial Number

The `--serial` flag sets the device serial number.

```bash
sudo fido2key --serial "KEYCHAINFIDO2-12345678"
```

Default: Auto-generated 16-character hexadecimal string.

Serial numbers should be unique per device instance to avoid conflicts when running multiple virtual authenticators.

## PIN Configuration

### Enabling PIN

The `--pin` flag enables PIN-based user verification.

```bash
sudo fido2key --pin
```

When enabled:
- Relying parties can request user verification via PIN
- PIN must be set before use (via `--set-pin` or WebAuthn PIN management)
- PIN has 8 retry attempts before lockout

### Setting Initial PIN

The `--set-pin` flag sets the initial PIN during startup. Requires `--pin`.

```bash
sudo fido2key --pin --set-pin 123456
```

PIN requirements:
- Minimum 4 characters
- No maximum length enforced by fido2key

**Security Note**: Passing PIN on command line may expose it in process lists. For production, consider setting PIN via WebAuthn client after startup.

## User Presence Configuration

### Interactive Mode

The `--interactive` flag enables terminal-based user presence prompts.

```bash
sudo fido2key --interactive
```

In interactive mode:
- User presence requests prompt for ENTER key
- PIN verification prompts for secure PIN entry (hidden input)
- Requires a TTY

**Constraints**:
- Requires stdin attached to a terminal

### User Presence Timeout

The `--timeout` flag sets the timeout for user presence requests.

```bash
sudo fido2key --interactive --timeout 60s
```

Default: `30s`

Accepts Go duration strings: `10s`, `1m`, `1m30s`

In auto-grant mode, this timeout is not used as requests are approved immediately.

## Key Backend Configuration

### Backend Selection

The `--backend` flag selects the cryptographic key backend.

| Value | Description |
|-------|-------------|
| `software` | Software-based keys in memory |
| `tpm2` | Hardware-backed keys via TPM 2.0 |

**Software Backend** (Default):
```bash
sudo fido2key --backend software
```

Features:
- Supports ES256, ES384, ES512, EdDSA algorithms
- Keys exportable in PKCS#8 format
- No hardware requirements

**TPM2 Backend**:
```bash
sudo fido2key --backend tpm2 --tpm-device /dev/tpmrm0
```

Features:
- Hardware-protected keys
- Supports ES256, ES384 algorithms
- Keys cannot be exported
- Requires TPM 2.0 hardware

### TPM Device Path

The `--tpm-device` flag specifies the TPM device when using the tpm2 backend.

```bash
sudo fido2key --backend tpm2 --tpm-device /dev/tpmrm0
```

Default: `/dev/tpmrm0`

Common paths:
- `/dev/tpmrm0` - TPM resource manager (recommended)
- `/dev/tpm0` - Direct TPM access (exclusive, may conflict with other TPM users)

## Attestation Configuration

### Attestation Format

The `--attestation` flag selects the attestation statement format.

| Value | Description | Requirements |
|-------|-------------|--------------|
| `none` | No attestation | Any backend |
| `packed` | Self-signed attestation | Any backend |
| `tpm` | TPM attestation | Requires `--backend tpm2` |

**None** (Default):
```bash
sudo fido2key --attestation none
```

Provides maximum privacy. Relying parties cannot verify authenticator identity.

**Packed**:
```bash
sudo fido2key --attestation packed
```

Self-signed attestation with x5c certificate chain. Suitable for testing attestation verification flows.

**TPM**:
```bash
sudo fido2key --backend tpm2 --attestation tpm
```

Hardware attestation with TPM-generated signature. Provides cryptographic proof of hardware protection.

## Logging Configuration

### Log Level

The `--log-level` flag sets the logging verbosity.

| Level | Description |
|-------|-------------|
| `debug` | Verbose debugging (HID packets, CTAP commands) |
| `info` | Normal operation messages |
| `warn` | Warnings only |
| `error` | Errors only |

```bash
sudo fido2key --log-level debug
```

Default: `info`

### Log File

The `--log-file` flag redirects logs to a file.

```bash
sudo fido2key --log-file /var/log/fido2key.log
```

Default: stdout

When running as a system service, a log file is recommended for troubleshooting.

## Configuration Validation

fido2key validates configuration at startup and reports errors:

**Invalid storage type**:
```
Configuration error: invalid storage type
```

**Missing storage path for file storage**:
```
Configuration error: storage path required for file storage
```

**TPM attestation without TPM backend**:
```
Configuration error: TPM attestation requires TPM2 backend
```

## Configuration Examples

### Minimal (Testing)

```bash
sudo fido2key
```

### Development with Debug Logging

```bash
sudo fido2key \
  --log-level debug \
  --name "Dev Key"
```

### CI/CD Integration

```bash
sudo fido2key \
  --storage memory \
  --pin --set-pin testpin \
  --log-level error
```

### Production Service

```bash
sudo fido2key \
  --storage file \
  --storage-path /var/lib/fido2key \
  --log-file /var/log/fido2key.log \
  --log-level info \
  --pin
```

### Hardware-Backed Security

```bash
sudo fido2key \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --attestation tpm \
  --storage file \
  --storage-path /var/lib/fido2key \
  --pin
```

### Interactive Manual Testing

```bash
sudo fido2key \
  --interactive \
  --timeout 60s \
  --log-level info \
  --pin --set-pin 123456
```

## Running as a System Service

fido2key does not include built-in daemon mode. Use your operating system's service manager to run fido2key as a background service.

### systemd (Linux)

Create `/etc/systemd/system/fido2key.service`:

```ini
[Unit]
Description=FIDO2 Authenticator (go-keychain)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fido2key \
  --storage file \
  --storage-path /var/lib/fido2key \
  --log-file /var/log/fido2key.log \
  --log-level info \
  --pin
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/fido2key /var/log/fido2key.log
DeviceAllow=/dev/uhid rw
DeviceAllow=/dev/tpmrm0 rw

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fido2key
sudo systemctl start fido2key
```

Check status:

```bash
sudo systemctl status fido2key
sudo journalctl -u fido2key -f
```

### OpenRC (Alpine/Gentoo)

Create `/etc/init.d/fido2key`:

```sh
#!/sbin/openrc-run

name="fido2key"
description="FIDO2 Authenticator (go-keychain)"
command="/usr/local/bin/fido2key"
command_args="--storage file --storage-path /var/lib/fido2key --log-file /var/log/fido2key.log --pin"
command_background=true
pidfile="/var/run/${RC_SVCNAME}.pid"
```

```bash
sudo chmod +x /etc/init.d/fido2key
sudo rc-update add fido2key default
sudo rc-service fido2key start
```

## Environment Considerations

### Permissions

fido2key requires access to:
- `/dev/uhid` - UHID device (root or `input` group membership)
- TPM device (if using tpm2 backend)
- Storage directory (if using file storage)

### Running as Non-Root

```bash
# Add user to input group
sudo usermod -a -G input $USER

# Set UHID device permissions (or use udev rules)
sudo chmod 660 /dev/uhid

# Run without sudo
fido2key --storage file --storage-path ~/.fido2key
```

### udev Rules

Create `/etc/udev/rules.d/99-uhid.rules`:

```
KERNEL=="uhid", GROUP="input", MODE="0660"
```

Reload rules:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```
