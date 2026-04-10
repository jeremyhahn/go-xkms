# fido2key - FIDO2 Key

fido2key is a software-based virtual FIDO2/WebAuthn security key that exposes itself as a USB HID device via Linux UHID. It provides a complete CTAP2 authenticator implementation for testing, development, and automation scenarios.

## Features

- **Full CTAP2 Implementation**: Supports MakeCredential, GetAssertion, ClientPIN, CredentialManagement, and more
- **USB HID Emulation**: Appears as a standard FIDO2 USB device via Linux UHID
- **Pluggable Key Backends**: Software (in-memory) or TPM 2.0 hardware-backed keys
- **Flexible User Presence**: Auto-grant mode for automation or interactive mode for manual testing
- **Multiple Attestation Formats**: none, packed (self-signed), or TPM attestation
- **Persistent Storage**: In-memory (volatile) or file-based (persistent) credential storage
- **PIN Support**: Optional PIN protection with configurable retries
- **Service Ready**: Designed to run under systemd, OpenRC, or other service managers

## Installation

### Building from Source

```bash
# Build the fido2key binary
make build-fido2key

# Or build with version information
make release-fido2key
```

### Requirements

- Linux kernel with UHID support (most modern kernels)
- Read/write access to `/dev/uhid` (typically requires root or membership in the `input` group)

## Quick Start

### Basic Usage (Testing/Automation)

Run a virtual FIDO2 device with auto-approve for all user presence requests:

```bash
# Start with in-memory storage (credentials lost on exit)
sudo fido2key

# Start with persistent file storage
sudo fido2key --storage file --storage-path /var/lib/fido2key
```

### Interactive Mode (Manual Testing)

Run with terminal prompts for user presence confirmation:

```bash
sudo fido2key --interactive
```

### With PIN Protection

```bash
# Enable PIN support with an initial PIN
sudo fido2key --pin --set-pin 123456
```

### As a System Service

```bash
# Install systemd service (see Configuration Guide for service file template)
sudo systemctl enable --now fido2key
```

## Configuration Reference

### Storage Options

| Flag | Default | Description |
|------|---------|-------------|
| `--storage` | `memory` | Storage type: `memory` or `file` |
| `--storage-path` | `/var/lib/fido2key` | Path for file storage (required when `--storage file`) |

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
| `--timeout` | `30s` | Timeout for user presence requests |

### Key Backend Options

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `software` | Key backend: `software` or `tpm2` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path (when `--backend tpm2`) |

### Attestation Options

| Flag | Default | Description |
|------|---------|-------------|
| `--attestation` | `none` | Attestation format: `none`, `packed`, or `tpm` |

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

fido2key supports two user presence modes that control how touch and PIN requests are handled.

### Auto-Grant Mode (Default)

In auto-grant mode, all user presence and verification requests are automatically approved. This is ideal for:

- Automated testing and CI/CD pipelines
- Development and debugging
- Integration testing with WebAuthn clients

```bash
# Auto-grant is the default
sudo fido2key
```

When PIN is enabled with auto-grant, the configured PIN is automatically provided for verification:

```bash
sudo fido2key --pin --set-pin 123456
```

### Interactive Mode

In interactive mode, the user is prompted via the terminal for each user presence or verification request. This simulates the physical touch experience of a real hardware key:

```bash
sudo fido2key --interactive
```

When a WebAuthn operation requires user presence, the terminal displays:

```
User presence required for register
   Relying Party: example.com
   User: alice@example.com

   Type 'y' and press ENTER to approve, or Ctrl+C to cancel:
```

For PIN verification, secure PIN entry is provided:

```
User verification required for authenticate
   Relying Party: example.com
   User: alice@example.com

   Enter PIN: ****
```

**Note**: Interactive mode requires a terminal and is not suitable for service deployments.

## Key Backends

fido2key supports pluggable key backends for credential key storage and cryptographic operations.

### Software Backend (Default)

The software backend stores keys in memory with full PKCS#8 export/import support. Features:

- **Algorithms**: ES256, ES384, ES512, EdDSA
- **Key Export**: Supported (PKCS#8 format)
- **Key Import**: Supported (PKCS#8 format)
- **Hardware Backed**: No
- **Attestation**: Self-attestation only (packed format)

```bash
# Software backend is the default
sudo fido2key --backend software
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
sudo fido2key --backend tpm2 --tpm-device /dev/tpmrm0
```

**Requirements**:
- TPM 2.0 hardware or software TPM (swtpm)
- Access to the TPM resource manager device (`/dev/tpmrm0`)

## Attestation Formats

fido2key supports three attestation statement formats for credential registration.

### None (Default)

No attestation statement is provided. The relying party cannot verify the authenticator's identity but this provides maximum privacy.

```bash
sudo fido2key --attestation none
```

### Packed

Self-signed attestation with an x5c certificate chain. The authenticator generates its own attestation certificate.

```bash
sudo fido2key --attestation packed
```

### TPM

Hardware-based attestation using TPM 2.0. Provides cryptographic proof that credentials are protected by a genuine TPM. Requires the TPM2 backend.

```bash
sudo fido2key --backend tpm2 --attestation tpm
```

**Note**: TPM attestation format requires `--backend tpm2`. Using `--attestation tpm` with the software backend will fail validation.

## Usage Examples

### Basic Testing with Auto-Approve

```bash
# Start virtual device for automated testing
sudo fido2key --log-level debug

# In another terminal, run your WebAuthn tests
```

### Interactive Mode for Manual Testing

```bash
# Start with interactive prompts
sudo fido2key --interactive --log-level info

# Follow terminal prompts when performing WebAuthn operations
```

### TPM-Backed Keys with Hardware Attestation

```bash
# Start with TPM2 backend and TPM attestation
sudo fido2key \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --attestation tpm \
  --storage file \
  --storage-path /var/lib/fido2key
```

### Running as a System Service

```bash
# Create systemd service (see Configuration Guide for complete template)
sudo fido2key \
  --log-file /var/log/fido2key.log \
  --log-level info \
  --storage file \
  --storage-path /var/lib/fido2key

# Or use systemd
sudo systemctl start fido2key
sudo systemctl status fido2key
```

### Development with Debug Logging

```bash
sudo fido2key \
  --log-level debug \
  --name "Dev FIDO2 Key" \
  --pin \
  --set-pin devpin123
```

### Full Debug Mode with Log File

For comprehensive debugging with all output captured to a file:

```bash
# Build and run with full debug logging
make build-fido2key && \
sudo ./build/bin/fido2key \
  -backend software \
  -pin \
  -set-pin 123456 \
  -interactive \
  -log-level debug \
  -storage memory \
  -log-file fido2.log
```

This configuration:
- Uses the software key backend (in-memory keys)
- Enables PIN protection with initial PIN `123456`
- Runs in interactive mode (prompts for user presence)
- Captures all debug logs to `fido2.log`
- Uses volatile memory storage (credentials lost on exit)

## Testing with WebAuthn Test Sites

Several public WebAuthn test servers are available to verify your virtual device works end-to-end with real relying parties.

### Recommended Test Sites

| Site | URL | Best For |
|------|-----|----------|
| **webauthn.io** | https://webauthn.io | Basic registration/authentication testing |
| **webauthn.me** | https://webauthn.me | Detailed debugging with request/response inspection |
| **passkeys.io** | https://passkeys.io | Passkey and resident credential testing |

### Setup

1. Start fido2key with interactive mode so you can approve each operation:

```bash
sudo fido2key --interactive --pin --set-pin 123456 --log-level debug
```

2. Open a Chromium-based browser (Chrome, Edge, Brave) and navigate to your chosen test site

### Registration (webauthn.io)

1. On webauthn.io, enter a username (e.g., `test-user`) and click **Register**
2. The browser prompts you to select a security key -- choose the virtual device
3. If PIN is enabled, enter your PIN in the browser dialog
4. In the fido2key terminal, type `y` and press ENTER to approve the user presence request
5. webauthn.io confirms registration success

### Authentication (webauthn.io)

1. Enter the same username and click **Authenticate**
2. Select the virtual device in the browser prompt
3. Enter PIN if prompted
4. Type `y` and press ENTER in the fido2key terminal to approve
5. webauthn.io confirms authentication success

### Testing Resident/Discoverable Credentials (passkeys.io)

Resident credentials allow usernameless authentication:

1. On passkeys.io, register a new passkey
2. The credential is stored on the virtual device
3. For authentication, the device can provide the credential without entering a username

### Advanced Testing (webauthn.me)

webauthn.me provides detailed inspection of WebAuthn requests and responses:

1. Navigate to https://webauthn.me
2. Use the registration/authentication forms
3. Inspect the full CBOR payloads and attestation objects
4. Useful for debugging protocol-level issues

### Automated Testing

For CI/CD or scripted testing, run fido2key in auto-grant mode (no `--interactive` flag) so all user presence requests are approved automatically:

```bash
# Start fido2key in background (auto-approve all requests)
sudo fido2key --pin --set-pin 123456 --log-file /var/log/fido2key.log

# Run browser automation (Playwright, Selenium, etc.) against test sites
# The virtual device responds to all WebAuthn prompts without manual intervention
```

### Troubleshooting

- **Browser doesn't see the device**: Ensure fido2key is running with root/uhid permissions and the UHID device was created (check `dmesg | tail`)
- **Registration fails**: Check fido2key debug logs for CTAP2 error codes
- **Chrome on Linux**: Chrome requires the device to appear under `/dev/hidraw*` -- verify with `ls /dev/hidraw*` after starting fido2key
- **Infinite loop / keepalives**: If the browser shows "waiting for key" indefinitely, check that the terminal is displaying the user presence prompt. Ensure you're running with `-interactive` flag and the terminal is visible.

## Signal Handling

fido2key handles the following signals gracefully:

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown

On shutdown, fido2key:
1. Stops the UHID event loop
2. Saves authenticator state (if using file storage)
3. Closes all resources

## Documentation

- [Configuration Guide](configuration.md) - Detailed configuration options
- [Architecture](architecture.md) - Component design and interfaces

## Related Packages

- `pkg/fido2/authenticator` - Core CTAP2 authenticator implementation
- `pkg/fido2/authenticator/keybackend` - Key backend interfaces
- `pkg/fido2/authenticator/keybackend/software` - Software key backend
- `pkg/fido2/authenticator/keybackend/tpm2` - TPM2 key backend
- `pkg/uhid` - Linux UHID interface for HID device emulation
