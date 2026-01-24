# vfido2 Configuration Guide

This guide covers all configuration options for vfido2 with detailed explanations and best practices.

## Configuration Methods

vfido2 is configured via command-line flags. All options have sensible defaults for quick startup.

## Storage Configuration

### Storage Type

The `--storage` flag selects the credential storage backend.

| Value | Description |
|-------|-------------|
| `memory` | In-memory storage (volatile, credentials lost on exit) |
| `file` | File-based storage (persistent across restarts) |

**Memory Storage** (Default):
```bash
sudo vfido2 --storage memory
```

Best for:
- Automated testing
- Development environments
- Ephemeral credentials

**File Storage**:
```bash
sudo vfido2 --storage file --storage-path /var/lib/vfido2
```

Best for:
- Production deployments
- Long-running services
- Credential persistence requirements

### Storage Path

When using file storage, `--storage-path` specifies the directory for credential data.

```bash
sudo vfido2 --storage file --storage-path /var/lib/vfido2
```

The directory is created if it does not exist. Ensure the vfido2 process has write permissions.

**Directory Structure**:
```
/var/lib/vfido2/
  vfido2/
    credentials/     # Stored credentials
    state.json       # Authenticator state (counters, PIN hash)
```

## Device Configuration

### Device Name

The `--name` flag sets the device name reported to the operating system.

```bash
sudo vfido2 --name "My Test FIDO2 Key"
```

Default: `Virtual FIDO2 Key (go-keychain)`

This name appears in:
- `lsusb` output
- Browser WebAuthn prompts
- System device managers

### Serial Number

The `--serial` flag sets the device serial number.

```bash
sudo vfido2 --serial "VFIDO2-12345678"
```

Default: Auto-generated 16-character hexadecimal string.

Serial numbers should be unique per device instance to avoid conflicts when running multiple virtual authenticators.

## PIN Configuration

### Enabling PIN

The `--pin` flag enables PIN-based user verification.

```bash
sudo vfido2 --pin
```

When enabled:
- Relying parties can request user verification via PIN
- PIN must be set before use (via `--set-pin` or WebAuthn PIN management)
- PIN has 8 retry attempts before lockout

### Setting Initial PIN

The `--set-pin` flag sets the initial PIN during startup. Requires `--pin`.

```bash
sudo vfido2 --pin --set-pin 123456
```

PIN requirements:
- Minimum 4 characters
- No maximum length enforced by vfido2

**Security Note**: Passing PIN on command line may expose it in process lists. For production, consider setting PIN via WebAuthn client after startup.

## User Presence Configuration

### Interactive Mode

The `--interactive` flag enables terminal-based user presence prompts.

```bash
sudo vfido2 --interactive
```

In interactive mode:
- User presence requests prompt for ENTER key
- PIN verification prompts for secure PIN entry (hidden input)
- Requires a TTY (not compatible with daemon mode)

**Constraints**:
- Cannot be combined with `--daemon`
- Requires stdin attached to a terminal

### User Presence Timeout

The `--up-timeout` flag sets the timeout for user presence requests.

```bash
sudo vfido2 --interactive --up-timeout 60s
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
sudo vfido2 --backend software
```

Features:
- Supports ES256, ES384, ES512, EdDSA algorithms
- Keys exportable in PKCS#8 format
- No hardware requirements

**TPM2 Backend**:
```bash
sudo vfido2 --backend tpm2 --tpm-device /dev/tpmrm0
```

Features:
- Hardware-protected keys
- Supports ES256, ES384 algorithms
- Keys cannot be exported
- Requires TPM 2.0 hardware

### TPM Device Path

The `--tpm-device` flag specifies the TPM device when using the tpm2 backend.

```bash
sudo vfido2 --backend tpm2 --tpm-device /dev/tpmrm0
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
sudo vfido2 --attestation none
```

Provides maximum privacy. Relying parties cannot verify authenticator identity.

**Packed**:
```bash
sudo vfido2 --attestation packed
```

Self-signed attestation with x5c certificate chain. Suitable for testing attestation verification flows.

**TPM**:
```bash
sudo vfido2 --backend tpm2 --attestation tpm
```

Hardware attestation with TPM-generated signature. Provides cryptographic proof of hardware protection.

## Daemon Configuration

### Running as Daemon

The `--daemon` (or `-d`) flag runs vfido2 in the background.

```bash
sudo vfido2 --daemon
```

When running as daemon:
- Process forks to background
- PID written to PID file
- Logging redirected to file (if `--log-file` specified)
- Interactive mode disabled

### PID File

The `--pid-file` flag specifies the PID file location.

```bash
sudo vfido2 --daemon --pid-file /var/run/vfido2.pid
```

Default: `/var/run/vfido2.pid`

PID file is:
- Created on startup
- Contains process ID
- Removed on clean shutdown

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
sudo vfido2 --log-level debug
```

Default: `info`

### Log File

The `--log-file` flag redirects logs to a file.

```bash
sudo vfido2 --log-file /var/log/vfido2.log
```

Default: stdout

When running as daemon, a log file is recommended for troubleshooting.

## Configuration Validation

vfido2 validates configuration at startup and reports errors:

**Invalid storage type**:
```
Configuration error: invalid storage type
```

**Missing storage path for file storage**:
```
Configuration error: storage path required for file storage
```

**Interactive mode with daemon**:
```
Configuration error: interactive mode cannot be used with daemon mode
```

**TPM attestation without TPM backend**:
```
Configuration error: TPM attestation requires TPM2 backend
```

## Configuration Examples

### Minimal (Testing)

```bash
sudo vfido2
```

### Development with Debug Logging

```bash
sudo vfido2 \
  --log-level debug \
  --name "Dev Key"
```

### CI/CD Integration

```bash
sudo vfido2 \
  --storage memory \
  --pin --set-pin testpin \
  --log-level error
```

### Production Daemon

```bash
sudo vfido2 \
  --daemon \
  --storage file \
  --storage-path /var/lib/vfido2 \
  --pid-file /var/run/vfido2.pid \
  --log-file /var/log/vfido2.log \
  --log-level info \
  --pin
```

### Hardware-Backed Security

```bash
sudo vfido2 \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --attestation tpm \
  --storage file \
  --storage-path /var/lib/vfido2 \
  --pin
```

### Interactive Manual Testing

```bash
sudo vfido2 \
  --interactive \
  --up-timeout 60s \
  --log-level info \
  --pin --set-pin 123456
```

## Environment Considerations

### Permissions

vfido2 requires access to:
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
vfido2 --storage file --storage-path ~/.vfido2
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
