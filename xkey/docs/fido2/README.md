# FIDO2/WebAuthn Security Key

xkey provides a **FIDO 2.1 compliant** FIDO2/WebAuthn security key that appears as a USB HID device via Linux UHID. It supports pinUvAuthProtocol 1 and 2 (Protocol 2 preferred), CTAPHID WINK capability, and works with both Chrome and Firefox. Cryptographic operations are backed by local software, a TPM 2.0, or a paired phone.

## Quick Start

```bash
# Software backend (testing/development)
sudo xkey fido2 --backend software

# TPM backend (local hardware security)
sudo xkey fido2 --backend tpm2

# Phone backend (paired Android device, TEE/StrongBox)
sudo xkey fido2 --backend phone

# With PIN and interactive mode
sudo xkey fido2 --backend software --pin --set-pin 123456 --interactive

# Unattended: a PIN-verified ceremony asks for no touch; the client sends the PIN
sudo xkey fido2 --require-touch=false --notify none
```

## Command Reference

```
xkey fido2 [flags]
```

Aliases: `xkey fido`

Subcommands: `start` (an alias for the bare command), `status` (exits non-zero
when no daemon is listening), `policy`, `profile`.

The flags below are **local to `xkey fido2`**, not persistent — they are not
available on `policy` or `profile`. `xkey fido2 start` accepts all of them: it
copies the daemon's flag set at registration time, so an invocation moves
between the bare form and `start` unchanged.

### Storage Options

| Flag | Default | Description |
|------|---------|-------------|
| `--storage` | `memory` | Storage type: `memory`, `file` or `barrier` |
| `--storage-path` | `./data` | Path for file storage |
| `--barrier-password` | (none) | Barrier password for the credential store |
| `--barrier-password-file` | (none) | File to read the barrier password from |

Any other `--storage` value is rejected. `file` requires `--storage-path`, and
`barrier` requires one of `--barrier-password` / `--barrier-password-file`.

### Device Options

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `xKey (go-xkms)` | Device name visible to the OS |
| `--serial` | (auto-generated) | Device serial number (16-char hex) |

### PIN Options

| Flag | Default | Description |
|------|---------|-------------|
| `--pin` | `true` | Enable PIN support (required for FIDO 2.1 credential management) |
| `--set-pin` | (none) | Set initial PIN (requires `--pin`) |
| `--unified-pin` | `true` | Propagate the host PIN service's user PIN to this authenticator's CTAP2 PIN hash (not a PKCS#11/file sync -- go-xkms has one governing PIN backend per device, see go-xkms#307) |

The Security Officer PIN is **not** configured from `xkey fido2`. It is managed
by the `xkey pin` command group — `xkey pin set-so`, `xkey pin change-so`,
`xkey pin status`, `xkey pin reset-lockout` — and over CTAP2 by the vendor
subcommands documented below.

### User Presence Options

| Flag | Default | Description |
|------|---------|-------------|
| `--interactive` | `false` | Enable interactive mode (prompt for touch/PIN) |
| `--require-touch` | `true` | Require touch even after PIN verification (like a hardware YubiKey) |
| `--timeout` | `30s` | Timeout for user presence requests |

### Key Backend Options

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `software` | Key backend: `software`, `tpm2`, or `phone` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path (when `--backend tpm2`) |
| `--phone-device` | (default paired phone) | Phone name or address (when `--backend phone`) |

### Attestation Options

| Flag | Default | Description |
|------|---------|-------------|
| `--attestation` | `none` | Attestation format: `none`, `packed`, or `tpm` |

### Chrome DevTools Bridge Options

Drives Chrome's virtual authenticator over CDP instead of creating a UHID
device — which means no `/dev/uhid` and no `sudo`, at the cost of only working
against a Chrome started with remote debugging.

| Flag | Default | Description |
|------|---------|-------------|
| `--cdp` | `false` | Enable the Chrome DevTools virtual authenticator bridge |
| `--cdp-host` | `localhost` | Chrome DevTools host |
| `--cdp-port` | `9222` | Chrome DevTools debugging port |

### IPC and Notification Options

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | (auto) | IPC socket path (`$XDG_RUNTIME_DIR/xkey/xkey.sock`) |
| `--notify` | `dialog` | Notification type: `dialog` (interactive), `passive` (desktop notification), `log`, or `none` |
| `--notify-command` | (none) | Custom notification command (overrides built-in notifications) |
| `--password-store` | `./data/staticpw` | Static password store path |
| `--default-password` | (none) | Password name to type on bare touch |

Every flag also has an `XKEY_FIDO2_*` environment variable and a config-file
key. Flags take precedence over environment variables, which take precedence
over the config file.

## User Presence Modes

### Unattended Mode

`--require-touch` defaults to `true`, so out of the box every ceremony waits
for a touch, exactly like a hardware key. Turning it off narrows that to
ceremonies that carried no PIN: after a verified PIN the daemon asks for no
touch, because the PIN was the deliberate act.

```bash
sudo xkey fido2 --require-touch=false --notify none
```

The PIN comes from the client. A browser collects it in its own dialog; the
CLI takes it without a terminal:

```bash
printf '%s' "$XKEY_PIN" | xkey auth login --pin-stdin \
    --server https://kms.example.com:8443 --email agent-build@example.com
```

A ceremony that carries no PIN still asks for presence, and a script answers
it with `xkey touch` against the daemon's IPC socket. Nothing reports user
verification the daemon did not perform: the UV flag is set only when a PIN
was verified or the key backend verified a human itself (a paired phone's
biometric). The flag that once claimed built-in verification for Chrome's
benefit was removed because that claim was false.

This is what makes the daemon suitable for:

- Automated testing and CI/CD pipelines
- Development and debugging
- Integration testing with WebAuthn clients

Leaving `--require-touch` at its default and approving each request with
`xkey touch` from a script is the other way to automate, and keeps the presence
check honest.

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
| `dialog` | Interactive D-Bus dialog (the default) |
| `passive` | Desktop notification, no prompt |
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

### Phone Backend

Proxy signing to a paired Android phone's secure hardware. Private keys never
leave the phone's TEE/StrongBox; the backend is a transparent proxy for the
cryptographic operations, and an operation may require biometric confirmation
on the handset.

- **Key storage**: Android TEE / StrongBox
- **Transport**: BLE, or TCP over ADB for USB, encrypted with Noise XX
- **Attestation**: Android Key Attestation via the platform verifier
- **Use Case**: Hardware-backed keys without a TPM or a hardware key

```bash
# Use the default paired phone
sudo xkey fido2 --backend phone

# Target a specific phone
sudo xkey fido2 --backend phone --phone-device "John's Pixel"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--phone-device` | (default paired phone) | Phone name or address to use |

The phone must be paired first — see [device pairing](../device/user.md).
`software`, `tpm2` and `phone` are the only values `--backend` accepts; anything
else fails with "fido2: invalid backend type".

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

The SO PIN is managed from the `xkey pin` command group — **not** from
`xkey fido2`, which registers no SO PIN flags:

```bash
xkey pin set-so           # set the SO PIN for the first time
xkey pin change-so        # change an existing SO PIN
xkey pin set-user         # set the User PIN (requires the SO PIN)
xkey pin change-user      # change the User PIN
xkey pin verify           # verify a PIN
xkey pin status           # whether each PIN is set, and retry counts
xkey pin reset-lockout    # clear a lockout
```

`xkey pin set-so` prompts for the PIN rather than taking it on the command
line, so it never lands in the shell history or process list. It accepts
`--data-dir` to target a specific store. The SO PIN must be at least 6
characters.

The same operations are reachable over CTAP2.1 through the vendor subcommands
below.

### Protected Operations

Operations requiring SO PIN authentication:

| Operation | CTAP2 Command | Description |
|-----------|---------------|-------------|
| Factory Reset | `authenticatorReset` (0x07) | Wipe all credentials and state |
| Replace Attestation Key | `VendorCmdReplaceAttestKey` (0x05) | Install new attestation certificate |
| Reset User PIN | `VendorCmdResetUserPIN` (0x04) | Reset locked user PIN |
| Change SO PIN | `VendorCmdChangeSOPIN` (0x02) | Update SO PIN |

### CTAP2.1 authenticatorConfig Command

xkey implements the CTAP2.1 `authenticatorConfig` command (0x0D) with standard and vendor subcommands.

**Standard Subcommands:**

| Subcommand | ID | Description |
|------------|----|-------------|
| EnableEnterpriseAttestation | 0x01 | Enable enterprise attestation mode |
| ToggleAlwaysUv | 0x02 | Toggle always-require-UV flag |
| SetMinPINLength | 0x03 | Set minimum PIN length policy |

**Vendor Subcommands:**

Vendor operations are nested, not flat. `authenticatorConfig` takes the single
vendor subcommand `AuthConfigCmdVendorPrototype` (0x80); the operation below is
then selected by a vendor command ID carried inside it. The IDs are therefore
small numbers, not `0x80`-range values (`pkg/authenticator/cmd_config.go`):

| Subcommand | ID | Description |
|------------|----|-------------|
| VendorCmdSetSOPIN | 0x01 | Initialize SO PIN (first-time setup) |
| VendorCmdChangeSOPIN | 0x02 | Change existing SO PIN |
| VendorCmdUnlockWithSOPIN | 0x03 | Unlock the KeyManager with the SO PIN |
| VendorCmdResetUserPIN | 0x04 | SO resets user PIN (requires SO unlock) |
| VendorCmdReplaceAttestKey | 0x05 | Replace attestation key (requires SO unlock) |
| VendorCmdGetSOPINRetries | 0x06 | Query SO PIN retry status |
| VendorCmdSetRPPolicy | 0x07 | Set or partially update a per-RP policy — only keys present in the request change, so a two-key request cannot clear the other overrides or lift a block (requires SO unlock) |
| VendorCmdGetRPPolicy | 0x08 | Get a per-RP policy |
| VendorCmdDeleteRPPolicy | 0x09 | Delete a per-RP policy (requires SO unlock) |
| VendorCmdListRPPolicies | 0x0A | List all per-RP policies |
| VendorCmdSetProfile | 0x0B | Set authenticator profile (requires SO unlock) |

The per-RP policy and profile operations are also exposed on the CLI as
`xkey fido2 policy list|set|get|delete` and `xkey fido2 profile set|show`.

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

The SO PIN is set separately from starting the daemon:

```bash
# Set the SO PIN, then the user PIN (prompts for each; never passed as a flag)
xkey pin set-so
xkey pin set-user

# Start the device with persistent storage
sudo xkey fido2 \
  --backend tpm2 \
  --pin --set-pin 123456 \
  --storage file \
  --storage-path /var/lib/xkey
```

#### SO PIN Reset of Locked User PIN

When a user PIN is locked after too many failed attempts:

1. Authenticate with SO PIN via `authenticatorConfig` (VendorCmdResetUserPIN, 0x04)
2. Provide new user PIN
3. User PIN counter is reset and new PIN is active

`xkey pin reset-lockout` is the CLI equivalent.

#### Replace Attestation Key

For enterprise deployments requiring custom attestation:

1. Authenticate with SO PIN via `authenticatorConfig` (VendorCmdReplaceAttestKey, 0x05)
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
