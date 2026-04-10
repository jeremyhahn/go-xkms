# FIDO2/WebAuthn Security Key

xkey provides a **FIDO 2.1 compliant** FIDO2/WebAuthn security key that appears as a USB HID device via Linux UHID. It supports pinUvAuthProtocol 1 and 2 (Protocol 2 preferred), CTAPHID WINK capability, and works with both Chrome and Firefox. Unlike hardware-only keys, xkey can use **any go-xkms backend** for cryptographic operations - from local software/TPM to cloud KMS services via xkmsd.

## Quick Start

```bash
# Software backend (testing/development)
sudo xkey fido2 --backend software

# TPM backend (local hardware security)
sudo xkey fido2 --backend tpm2

# xkmsd backend (any go-xkms backend)
sudo xkey fido2 --backend xkmsd --xkmsd-url https://localhost:8443

# With PIN and interactive mode
sudo xkey fido2 --backend software --pin --set-pin 123456 --interactive
```

## Command Reference

```
xkey fido2 [flags]
```

Aliases: `xkey fido`

### Storage Options

| Flag | Default | Description |
|------|---------|-------------|
| `--storage` | `memory` | Storage type: `memory` or `file` |
| `--storage-path` | `/var/lib/xkey` | Path for file storage |

### Device Options

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `xkey (go-xkms)` | Device name visible to the OS |
| `--serial` | (auto-generated) | Device serial number (16-char hex) |

### PIN Options

| Flag | Default | Description |
|------|---------|-------------|
| `--pin` | `false` | Enable PIN support |
| `--set-pin` | (none) | Set initial PIN (requires `--pin`) |

### Security Officer (SO) PIN Options

| Flag | Default | Description |
|------|---------|-------------|
| `--so-pin` | `false` | Enable SO PIN support for admin operations |
| `--set-so-pin` | (none) | Set initial SO PIN (requires `--so-pin`) |
| `--so-pin-retries` | `8` | Maximum SO PIN retry attempts before lockout |

### User Presence Options

| Flag | Default | Description |
|------|---------|-------------|
| `--interactive` | `false` | Enable interactive mode (prompt for touch/PIN) |
| `--timeout` | `30s` | Timeout for user presence requests |

### Key Backend Options

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `software` | Key backend: `software`, `tpm2`, or `xkmsd` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path (when `--backend tpm2`) |
| `--xkmsd-url` | `https://localhost:8443` | xkmsd URL (when `--backend xkmsd`) |
| `--xkmsd-ca` | (system) | CA certificate for xkmsd TLS |
| `--xkmsd-cert` | (none) | Client certificate for mTLS |
| `--xkmsd-key` | (none) | Client key for mTLS |

### Attestation Options

| Flag | Default | Description |
|------|---------|-------------|
| `--attestation` | `none` | Attestation format: `none`, `packed`, or `tpm` |

### IPC and Notification Options

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | (auto) | IPC socket path (`$XDG_RUNTIME_DIR/xkey/xkey.sock`) |
| `--notify` | `dialog` | Notification type: `dialog`, `log`, or `none` |
| `--notify-command` | (none) | Custom notification command (overrides `--notify`) |
| `--password-store` | `/var/lib/xkey/staticpw` | Static password store path |
| `--default-password` | (none) | Password name to type on bare touch |

## User Presence Modes

### Auto-Grant Mode (Default)

All user presence and verification requests are automatically approved. Ideal for:

- Automated testing and CI/CD pipelines
- Development and debugging
- Integration testing with WebAuthn clients

```bash
sudo xkey fido2
```

When PIN is enabled with auto-grant, the configured PIN is automatically provided:

```bash
sudo xkey fido2 --pin --set-pin 123456
```

### Interactive Mode

The user is prompted via the terminal for each request:

```bash
sudo xkey fido2 --interactive
```

When a WebAuthn operation requires user presence:

```
User presence required for register
   Relying Party: example.com
   User: alice@example.com

   Type 'y' and press ENTER to approve, or Ctrl+C to cancel:
```

For PIN verification:

```
User verification required for authenticate
   Relying Party: example.com
   User: alice@example.com

   Enter PIN: ****
```

**Note**: Interactive mode requires a terminal and is not suitable for service deployments.

### Socket-Based Mode (Daemon)

For running as a background service with desktop notifications:

```bash
sudo xkey fido2 --notify dialog
```

When a WebAuthn operation requires user presence:
1. Desktop notification appears: "xkey: Touch required for example.com"
2. User runs `xkey touch` to approve
3. Operation completes

This mode supports:
- D-Bus desktop notifications (Linux)
- Custom notification commands
- Remote approval via IPC

## Touch Command

The `xkey touch` command approves pending user presence requests or types passwords.

```bash
xkey touch [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--password` | (none) | Name of password to type |
| `--socket` | (auto) | IPC socket path |

**Behavior:**
1. If WebAuthn operation pending → approves user presence
2. If `--password` specified → types that password via virtual keyboard
3. If `--default-password` configured in daemon → types default password
4. Otherwise → reports "no pending request"

**Examples:**

```bash
# Approve pending WebAuthn request
xkey touch

# Type a specific password
xkey touch --password "DatabaseProd"
```

## Notification System

When running in daemon mode, xkey sends desktop notifications when touch is required.

### Notification Types

| Type | Description |
|------|-------------|
| `dialog` | D-Bus desktop notification (default on Linux) |
| `log` | Log message only |
| `none` | No notifications |

### Custom Notification Command

Use `--notify-command` with template variables:

| Variable | Description |
|----------|-------------|
| `%o` | Operation (`register` or `authenticate`) |
| `%r` | Relying Party ID |
| `%n` | Relying Party Name |
| `%u` | User Name |

```bash
sudo xkey fido2 --notify-command 'notify-send -u critical "xkey" "Touch for %n (%o)"'
```

## Key Backends

xkey supports multiple backend modes for cryptographic operations.

### Software Backend (Default)

Local software-based keys, ideal for testing and development.

- **Algorithms**: ES256, ES384, ES512, EdDSA
- **Key Export**: Supported (PKCS#8 format)
- **Hardware Backed**: No
- **Use Case**: Development, testing, non-critical applications

```bash
sudo xkey fido2 --backend software
```

### TPM2 Backend

Hardware-backed keys via local TPM 2.0.

- **Algorithms**: ES256, ES384
- **Key Export**: Not supported (hardware-protected)
- **Hardware Backed**: Yes
- **Attestation**: TPM attestation with certificate chain
- **Use Case**: Hardware security without cloud dependency

```bash
sudo xkey fido2 --backend tpm2 --tpm-device /dev/tpmrm0
```

**Requirements**:
- TPM 2.0 hardware or software TPM (swtpm)
- Access to the TPM resource manager device (`/dev/tpmrm0`)

### xkmsd Backend (All Backends)

Connect to the xkmsd service to use **any** go-xkms backend:

- **Hardware HSMs**: PKCS#11, YubiKey, SmartCard-HSM, Nitrokey
- **Cloud KMS**: AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault
- **Software**: PKCS#8, memory
- **Use Case**: Enterprise deployments, centralized key management

```bash
# Start xkmsd with your desired backend
xkmsd serve --config /etc/xkmsd/config.yaml

# Connect xkey to xkmsd
sudo xkey fido2 --backend xkmsd --xkmsd-url https://localhost:8443
```

| Flag | Default | Description |
|------|---------|-------------|
| `--xkmsd-url` | `https://localhost:8443` | xkmsd service URL |
| `--xkmsd-ca` | (system) | CA certificate for TLS |
| `--xkmsd-cert` | (none) | Client certificate for mTLS |
| `--xkmsd-key` | (none) | Client key for mTLS |

**Example with AWS KMS via xkmsd:**

```yaml
# /etc/xkmsd/config.yaml
backends:
  fido2:
    type: awskms
    region: us-east-1
    key_id: alias/xkey-fido2
```

```bash
sudo xkey fido2 --backend xkmsd --xkmsd-url https://xkmsd.internal:8443
```

## Attestation Formats

### None (Default)

No attestation statement is provided. Maximum privacy but the relying party cannot verify the authenticator's identity.

```bash
sudo xkey fido2 --attestation none
```

### Packed

Self-signed attestation with an x5c certificate chain.

```bash
sudo xkey fido2 --attestation packed
```

### TPM

Hardware-based attestation using TPM 2.0. Requires the TPM2 backend.

```bash
sudo xkey fido2 --backend tpm2 --attestation tpm
```

## Usage Examples

### Basic Testing

```bash
# Start virtual device for automated testing
sudo xkey fido2 --log-level debug
```

### Interactive Manual Testing

```bash
# Start with interactive prompts
sudo xkey fido2 --interactive --log-level info
```

### TPM-Backed with Hardware Attestation

```bash
sudo xkey fido2 \
  --backend tpm2 \
  --tpm-device /dev/tpmrm0 \
  --attestation tpm \
  --storage file \
  --storage-path /var/lib/xkey
```

### System Service

```bash
sudo xkey fido2 \
  --log-file /var/log/xkey.log \
  --log-level info \
  --storage file \
  --storage-path /var/lib/xkey
```

### Full Debug Mode

```bash
make build-xkey && \
sudo ./build/bin/xkey fido2 \
  --backend software \
  --pin \
  --set-pin 123456 \
  --interactive \
  --log-level debug \
  --storage memory \
  --log-file fido2.log
```

## Testing with WebAuthn Sites

### Recommended Test Sites

| Site | URL | Best For |
|------|-----|----------|
| **webauthn.io** | https://webauthn.io | Basic registration/authentication |
| **webauthn.me** | https://webauthn.me | Request/response inspection |
| **passkeys.io** | https://passkeys.io | Passkey and resident credentials |

### Setup

1. Start xkey with interactive mode:

```bash
sudo xkey fido2 --interactive --pin --set-pin 123456 --log-level debug
```

2. Open Chrome, Edge, Brave, or Firefox and navigate to the test site

### Registration (webauthn.io)

1. Enter a username and click **Register**
2. Select the virtual device in the browser prompt
3. Enter your PIN in the browser dialog
4. Type `y` and press ENTER in the xkey terminal
5. Registration confirms success

### Authentication (webauthn.io)

1. Enter the same username and click **Authenticate**
2. Select the virtual device
3. Enter PIN if prompted
4. Type `y` and press ENTER to approve
5. Authentication confirms success

### Resident Credentials (passkeys.io)

Resident credentials allow usernameless authentication:

1. Register a new passkey on passkeys.io
2. The credential is stored on the virtual device
3. For authentication, the device provides the credential without username entry

### Automated Testing

For CI/CD, run in auto-grant mode:

```bash
sudo xkey fido2 --pin --set-pin 123456 --log-file /var/log/xkey.log &

# Run browser automation (Playwright, Selenium, etc.)
```

## Browser Compatibility

| Browser | Protocol Used | Notes |
|---------|--------------|-------|
| Chrome | Protocol 2 | Chrome requires pinUvAuthProtocol 2 for FIDO 2.1 authenticators |
| Firefox | Protocol 1 or 2 | Works with either protocol version |

The authenticator advertises `pinUvAuthProtocols: [2, 1]` in GetInfo. The browser selects the protocol version per-request -- this is the standard CTAP2 negotiation mechanism.

## Troubleshooting

- **Browser doesn't see the device**: Ensure xkey is running with root/uhid permissions and UHID device was created (`dmesg | tail`)
- **Registration fails**: Check xkey debug logs for CTAP2 error codes
- **Chrome rejects the authenticator**: Verify pinUvAuthProtocol 2 is advertised in GetInfo (required by Chrome for FIDO 2.1)
- **Chrome on Linux**: Verify device appears under `/dev/hidraw*`
- **Infinite loop / keepalives**: Ensure `--interactive` flag is set and terminal is visible

## Security Officer (SO) PIN

The SO PIN provides administrative access for protected operations that should not be available to regular users.

### Overview

The SO PIN (Security Officer PIN) protects privileged operations:

- **Factory reset** - Wipe all credentials and state
- **Attestation key replacement** - Install new attestation certificates
- **User PIN reset** - Reset a locked user PIN without knowing the old PIN
- **SO PIN management** - Change the SO PIN itself

### Key Hierarchy

xkey uses a hierarchical key wrapping scheme that allows both SO and User access paths:

```
SO PIN                          User PIN
   |                                |
   v (Argon2id)                     v (Argon2id)
  SMK (SO Master Key)              UMK (User Master Key)
   |                                |
   v (AES-GCM unwrap)               |
  AK (Admin Key)                    |
   |                                |
   +---> Attestation Key            |
   |                                |
   v (AES-GCM unwrap)               v (AES-GCM unwrap)
  CMK (Credential Master Key) <-----+
   |
   v (AES-GCM unwrap)
  Credential Keys
```

**Key Components:**
- **SMK (SO Master Key)**: Derived from SO PIN via Argon2id
- **AK (Admin Key)**: Wrapped by SMK, protects attestation key and CMK
- **UMK (User Master Key)**: Derived from User PIN via Argon2id
- **CMK (Credential Master Key)**: Dual-wrapped by both AK and UMK, enabling access from either path
- **Credential Keys**: Individual credential signing keys, wrapped by CMK

### SO PIN Commands

xkey implements CTAP2.1 vendor-specific subcommands for SO PIN management.

#### Initialize SO PIN

Set the SO PIN during initial device setup:

```bash
# Via command line
sudo xkey fido2 --so-pin --set-so-pin "SecureAdminPIN123!"

# Via CTAP2.1 authenticatorConfig (vendorSetSOPIN)
# Subcommand: 0x80
```

#### Change SO PIN

Change an existing SO PIN:

```bash
# Via CTAP2.1 authenticatorConfig (vendorChangeSOPIN)
# Subcommand: 0x81
# Requires: current SO PIN
```

#### Get SO PIN Retries

Query remaining SO PIN attempts:

```bash
# Via CTAP2.1 authenticatorConfig (vendorGetSOPINRetries)
# Subcommand: 0x85
# Returns: remaining retry count, locked status
```

### Protected Operations

Operations requiring SO PIN authentication:

| Operation | CTAP2 Command | Description |
|-----------|---------------|-------------|
| Factory Reset | `authenticatorReset` (0x07) | Wipe all credentials and state |
| Replace Attestation Key | `vendorReplaceAttestKey` (0x84) | Install new attestation certificate |
| Reset User PIN | `vendorResetUserPIN` (0x83) | Reset locked user PIN |
| Change SO PIN | `vendorChangeSOPIN` (0x81) | Update SO PIN |

### CTAP2.1 authenticatorConfig Command

xkey implements the CTAP2.1 `authenticatorConfig` command (0x0D) with standard and vendor subcommands.

**Standard Subcommands:**

| Subcommand | ID | Description |
|------------|----|-------------|
| EnableEnterpriseAttestation | 0x01 | Enable enterprise attestation mode |
| ToggleAlwaysUv | 0x02 | Toggle always-require-UV flag |
| SetMinPINLength | 0x03 | Set minimum PIN length policy |

**Vendor Subcommands (0x80+):**

| Subcommand | ID | Description |
|------------|----|-------------|
| VendorSetSOPIN | 0x80 | Initialize SO PIN (first-time setup) |
| VendorChangeSOPIN | 0x81 | Change existing SO PIN |
| VendorUnlockWithSOPIN | 0x82 | Unlock authenticator with SO PIN |
| VendorResetUserPIN | 0x83 | SO resets user PIN |
| VendorReplaceAttestKey | 0x84 | Replace attestation key |
| VendorGetSOPINRetries | 0x85 | Query SO PIN retry status |

### deviceConfig FIDO2 Extension

xkey includes the `deviceConfig` extension in authenticator data, allowing relying parties to verify device configuration integrity.

**Extension ID:** `deviceConfig`

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `minPINLength` | uint | Configured minimum PIN length |
| `alwaysUV` | bool | Always-require-UV setting |
| `pinProtocol` | uint | Active PIN protocol version (1 or 2) |
| `attestedHash` | bytes | Hash of config at attestation time |
| `currentHash` | bytes | Hash of current configuration |
| `tampered` | bool | True if currentHash != attestedHash |
| `vendor` | map | Vendor-specific configuration data |

**Usage:**

The extension is included in authenticator data for both `MakeCredential` and `GetAssertion` responses when the relying party requests it:

```javascript
// WebAuthn registration request
const options = {
  publicKey: {
    // ...
    extensions: {
      deviceConfig: true
    }
  }
};
```

**Tamper Detection:**

Relying parties can detect configuration changes by comparing `attestedHash` with `currentHash`. If they differ, the `tampered` flag is set to `true`, indicating the device configuration has changed since the credential was created.

### Usage Examples

#### Initialize Device with SO PIN

```bash
# Start device with both user PIN and SO PIN
sudo xkey fido2 \
  --backend tpm2 \
  --pin --set-pin 123456 \
  --so-pin --set-so-pin "SecureAdmin123!" \
  --storage file \
  --storage-path /var/lib/xkey
```

#### SO PIN Reset of Locked User PIN

When a user PIN is locked after too many failed attempts:

1. Authenticate with SO PIN via `authenticatorConfig` (vendorResetUserPIN, 0x83)
2. Provide new user PIN
3. User PIN counter is reset and new PIN is active

#### Replace Attestation Key

For enterprise deployments requiring custom attestation:

1. Authenticate with SO PIN via `authenticatorConfig` (vendorReplaceAttestKey, 0x84)
2. Provide new attestation private key and certificate chain
3. New attestation key is wrapped and stored

### Security Considerations

- **SO PIN Strength**: Use a strong SO PIN (12+ characters) with mixed case, numbers, and symbols
- **Separate from User PIN**: SO PIN and User PIN should be different
- **Limited Retries**: SO PIN has limited retry attempts (default: 8) before permanent lockout
- **No Recovery**: If SO PIN is locked, administrative operations are permanently disabled
- **Audit Logging**: SO PIN operations are logged for compliance

## Signal Handling

xkey handles these signals gracefully:

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown

On shutdown:
1. Stops the UHID event loop
2. Saves authenticator state (if using file storage)
3. Closes all resources
