# vfido2 - Virtual FIDO2/WebAuthn Authenticator

vfido2 is a software-based virtual FIDO2/WebAuthn security key that exposes itself as a USB HID device via Linux UHID. It provides a complete CTAP2 authenticator implementation for testing, development, and automation scenarios.

## Features

- **Full CTAP2 Implementation**: Supports MakeCredential, GetAssertion, ClientPIN, CredentialManagement, and more
- **USB HID Emulation**: Appears as a standard FIDO2 USB device via Linux UHID
- **Pluggable Key Backends**: Software (in-memory) or TPM 2.0 hardware-backed keys
- **Flexible User Presence**: Auto-grant mode for automation or interactive mode for manual testing
- **Multiple Attestation Formats**: none, packed (self-signed), or TPM attestation
- **Persistent Storage**: In-memory (volatile) or file-based (persistent) credential storage
- **PIN Support**: Optional PIN protection with configurable retries
- **Daemon Mode**: Run as a background service with PID file management

## Installation

### Building from Source

```bash
# Build the vfido2 binary
make build-vfido2

# Or build with version information
make release-vfido2
```

### Requirements

- Linux kernel with UHID support (most modern kernels)
- Read/write access to `/dev/uhid` (typically requires root or membership in the `input` group)

## Quick Start

### Basic Usage (Testing/Automation)

Run a virtual FIDO2 device with auto-approve for all user presence requests:

```bash
# Start with in-memory storage (credentials lost on exit)
sudo vfido2

# Start with persistent file storage
sudo vfido2 --storage file --storage-path /var/lib/vfido2
```

### Interactive Mode (Manual Testing)

Run with terminal prompts for user presence confirmation:

```bash
sudo vfido2 --interactive
```

### With PIN Protection

```bash
# Enable PIN support with an initial PIN
sudo vfido2 --pin --set-pin 123456
```

### As a Daemon

```bash
# Run in background
sudo vfido2 --daemon --pid-file /var/run/vfido2.pid --log-file /var/log/vfido2.log
```

## Configuration Reference

### Storage Options

| Flag | Default | Description |
|------|---------|-------------|
| `--storage` | `memory` | Storage type: `memory` or `file` |
| `--storage-path` | `/var/lib/vfido2` | Path for file storage (required when `--storage file`) |

### Device Options

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `Virtual FIDO2 Key (go-keychain)` | Device name visible to the OS |
| `--serial` | (auto-generated) | Device serial number (16-char hex) |

### PIN Options

| Flag | Default | Description |
|------|---------|-------------|
| `--pin` | `false` | Enable PIN support |
| `--set-pin` | (none) | Set initial PIN (requires `--pin`) |

### User Presence Options

| Flag | Default | Description |
|------|---------|-------------|
| `--interactive` | `false` | Enable interactive mode (prompt for touch/PIN) |
| `--up-timeout` | `30s` | Timeout for user presence requests |

### Key Backend Options

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `software` | Key backend: `software` or `tpm2` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path (when `--backend tpm2`) |

### Attestation Options

| Flag | Default | Description |
|------|---------|-------------|
| `--attestation` | `none` | Attestation format: `none`, `packed`, or `tpm` |

### Daemon Options

| Flag | Default | Description |
|------|---------|-------------|
| `--daemon`, `-d` | `false` | Run as daemon (background) |
| `--pid-file` | `/var/run/vfido2.pid` | PID file path |

### Logging Options

| Flag | Default | Description |
|------|---------|-------------|
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--log-file` | (stdout) | Log file path (empty for stdout) |

### Other Options

| Flag | Description |
|------|-------------|
| `--version`, `-v` | Show version information |

## User Presence Modes

vfido2 supports two user presence modes that control how touch and PIN requests are handled.

### Auto-Grant Mode (Default)

In auto-grant mode, all user presence and verification requests are automatically approved. This is ideal for:

- Automated testing and CI/CD pipelines
- Development and debugging
- Integration testing with WebAuthn clients

```bash
# Auto-grant is the default
sudo vfido2
```

When PIN is enabled with auto-grant, the configured PIN is automatically provided for verification:

```bash
sudo vfido2 --pin --set-pin 123456
```

### Interactive Mode

In interactive mode, the user is prompted via the terminal for each user presence or verification request. This simulates the physical touch experience of a real hardware key:

```bash
sudo vfido2 --interactive
```

When a WebAuthn operation requires user presence, the terminal displays:

```
User presence required for register
   Relying Party: example.com
   User: alice@example.com

   Press ENTER to approve, or Ctrl+C to cancel...
```

For PIN verification, secure PIN entry is provided:

```
User verification required for authenticate
   Relying Party: example.com
   User: alice@example.com

   Enter PIN: ****
```

**Note**: Interactive mode cannot be used with daemon mode (`--daemon`) as it requires a terminal.

## Key Backends

vfido2 supports pluggable key backends for credential key storage and cryptographic operations.

### Software Backend (Default)

The software backend stores keys in memory with full PKCS#8 export/import support. Features:

- **Algorithms**: ES256, ES384, ES512, EdDSA
- **Key Export**: Supported (PKCS#8 format)
- **Key Import**: Supported (PKCS#8 format)
- **Hardware Backed**: No
- **Attestation**: Self-attestation only (packed format)

```bash
# Software backend is the default
sudo vfido2 --backend software
```

### TPM2 Backend

The TPM2 backend uses hardware-backed keys via TPM 2.0. Features:

- **Algorithms**: ES256, ES384
- **Key Export**: Not supported (hardware-protected)
- **Key Import**: Not supported
- **Hardware Backed**: Yes
- **Attestation**: TPM attestation with certificate chain

```bash
# Use TPM2 backend
sudo vfido2 --backend tpm2 --tpm-device /dev/tpmrm0
```

**Requirements**:
- TPM 2.0 hardware or software TPM (swtpm)
- Access to the TPM resource manager device (`/dev/tpmrm0`)

## Attestation Formats

vfido2 supports three attestation statement formats for credential registration.

### None (Default)

No attestation statement is provided. The relying party cannot verify the authenticator's identity but this provides maximum privacy.

```bash
sudo vfido2 --attestation none
```

### Packed

Self-signed attestation with an x5c certificate chain. The authenticator generates its own attestation certificate.

```bash
sudo vfido2 --attestation packed
```

### TPM

Hardware-based attestation using TPM 2.0. Provides cryptographic proof that credentials are protected by a genuine TPM. Requires the TPM2 backend.

```bash
sudo vfido2 --backend tpm2 --attestation tpm
```

**Note**: TPM attestation format requires `--backend tpm2`. Using `--attestation tpm` with the software backend will fail validation.

## Usage Examples

### Basic Testing with Auto-Approve

```bash
# Start virtual device for automated testing
sudo vfido2 --log-level debug

# In another terminal, run your WebAuthn tests
```

### Interactive Mode for Manual Testing

```bash
# Start with interactive prompts
sudo vfido2 --interactive --log-level info

# Follow terminal prompts when performing WebAuthn operations
```

### TPM-Backed Keys with Hardware Attestation

```bash
# Start with TPM2 backend and TPM attestation
sudo vfido2 \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --attestation tpm \
  --storage file \
  --storage-path /var/lib/vfido2
```

### Running as a Daemon

```bash
# Start as background service
sudo vfido2 \
  --daemon \
  --pid-file /var/run/vfido2.pid \
  --log-file /var/log/vfido2.log \
  --log-level info \
  --storage file \
  --storage-path /var/lib/vfido2

# Check status
cat /var/run/vfido2.pid

# Stop the daemon
sudo kill $(cat /var/run/vfido2.pid)
```

### Development with Debug Logging

```bash
sudo vfido2 \
  --log-level debug \
  --name "Dev FIDO2 Key" \
  --pin \
  --set-pin devpin123
```

## Signal Handling

vfido2 handles the following signals gracefully:

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown

On shutdown, vfido2:
1. Stops the UHID event loop
2. Saves authenticator state (if using file storage)
3. Closes all resources
4. Removes the PID file (if running as daemon)

## Documentation

- [Configuration Guide](configuration.md) - Detailed configuration options
- [Architecture](architecture.md) - Component design and interfaces

## Related Packages

- `pkg/fido2/authenticator` - Core CTAP2 authenticator implementation
- `pkg/fido2/authenticator/keybackend` - Key backend interfaces
- `pkg/fido2/authenticator/keybackend/software` - Software key backend
- `pkg/fido2/authenticator/keybackend/tpm2` - TPM2 key backend
- `pkg/uhid` - Linux UHID interface for HID device emulation
