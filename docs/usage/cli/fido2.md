# FIDO2 CLI Commands

The `fido2` command group provides tools for managing FIDO2/WebAuthn security keys for authentication and key derivation.

## Overview

FIDO2 (Fast Identity Online 2) is a passwordless authentication standard that uses hardware security keys. The go-keychain FIDO2 CLI enables:

- Device enumeration and discovery
- Credential registration with security keys
- Authentication using registered credentials
- Key derivation for encryption operations

## Supported Devices

The FIDO2 implementation supports a wide range of FIDO2-certified security keys including:

- **YubiKey** (Yubico) - Vendor ID: 0x1050
- **Feitian** - Vendor ID: 0x096E
- **Nitrokey** - Vendor ID: 0x20A0
- **Plug-up** - Vendor ID: 0x2581
- **Token2** - Vendor ID: 0x24DC
- **Google Titan** and other FIDO Alliance devices

All devices must support the FIDO2/CTAP2 protocol over HID (Human Interface Device).

## Commands

### fido2 list-devices

List all connected FIDO2-compatible security keys.

**Usage:**
```bash
go-keychain fido2 list-devices
```

**Output:**
```
FIDO2 Devices:
  Path:         /dev/hidraw0
  Vendor ID:    0x1050
  Product ID:   0x0407
  Manufacturer: Yubico
  Product:      YubiKey 5 NFC
  Serial:       12345678
  Transport:    usb
```

**JSON Output:**
```bash
go-keychain fido2 list-devices --output json
```
```json
{
  "devices": [
    {
      "path": "/dev/hidraw0",
      "vendor_id": "0x1050",
      "product_id": "0x0407",
      "manufacturer": "Yubico",
      "product": "YubiKey 5 NFC",
      "serial_number": "12345678",
      "transport": "usb"
    }
  ]
}
```

**Exit Codes:**
- `0` - Success (devices found)
- `0` - Success (no devices found, message printed)
- `1` - Error enumerating devices

---

### fido2 wait-device

Wait for a FIDO2 security key to be connected to the system.

**Usage:**
```bash
go-keychain fido2 wait-device [flags]
```

**Flags:**
- `--timeout duration` - Maximum time to wait for a device (default: 60s)

**Examples:**

Wait up to 60 seconds (default):
```bash
go-keychain fido2 wait-device
```

Wait up to 2 minutes:
```bash
go-keychain fido2 wait-device --timeout 2m
```

**Output:**
```
Waiting for FIDO2 device... (press Ctrl+C to cancel)
Device found: YubiKey 5 NFC (/dev/hidraw0)
```

**Exit Codes:**
- `0` - Device connected successfully
- `1` - Timeout or error waiting for device

---

### fido2 register

Register a new FIDO2 credential for a user. This creates a credential that can be used for authentication and key derivation.

**Usage:**
```bash
go-keychain fido2 register <username> [flags]
```

**Arguments:**
- `username` - Username to register the credential for

**Flags:**
- `--rp-id string` - Relying Party ID (default: "go-keychain")
- `--rp-name string` - Relying Party name (default: "Go Keychain")
- `--display-name string` - User display name (defaults to username)
- `--timeout duration` - Timeout for user presence confirmation (default: 30s)
- `--device string` - Specific device path to use (optional)
- `--user-verification` - Require user verification (PIN) (default: false)

**Examples:**

Basic registration:
```bash
go-keychain fido2 register alice
```

Registration with custom relying party:
```bash
go-keychain fido2 register alice \
  --rp-id example.com \
  --rp-name "Example App" \
  --display-name "Alice Smith"
```

Registration requiring PIN verification:
```bash
go-keychain fido2 register alice --user-verification
```

Registration with specific device:
```bash
go-keychain fido2 register alice --device /dev/hidraw0
```

**Output:**
```
Registering FIDO2 credential for user: alice
Please touch your security key to register...
Credential registered successfully

Credential ID: pQECAyYgASFYIL8...[base64]
Public Key:    pQECAyYgASFYIL8...[base64]
AAGUID:        ee882879-721c-4913-9775-3dfcce97072a
Sign Count:    0
Salt:          rT8vN2kL...[base64]

User:
  Name:         alice
  Display Name: alice

Relying Party:
  ID:   go-keychain
  Name: Go Keychain

Created: 2025-12-24T10:30:45Z
```

**JSON Output:**
```bash
go-keychain fido2 register alice --output json
```
```json
{
  "credential_id": "pQECAyYgASFYIL8...",
  "public_key": "pQECAyYgASFYIL8...",
  "aaguid": "ee882879-721c-4913-9775-3dfcce97072a",
  "sign_count": 0,
  "salt": "rT8vN2kL...",
  "user": {
    "id": "YWxpY2U=",
    "name": "alice",
    "display_name": "alice"
  },
  "relying_party": {
    "id": "go-keychain",
    "name": "Go Keychain"
  },
  "created": "2025-12-24T10:30:45Z"
}
```

**Important:** Save the credential ID and salt values - they are required for authentication.

**Exit Codes:**
- `0` - Registration successful
- `1` - Registration failed (timeout, device error, user cancelled)

---

### fido2 authenticate

Authenticate using a previously registered FIDO2 credential and derive a secret key.

**Usage:**
```bash
go-keychain fido2 authenticate [flags]
```

**Flags:**
- `--credential-id string` - Credential ID from registration (required, base64 or hex)
- `--salt string` - Salt value from registration (required, base64 or hex)
- `--rp-id string` - Relying Party ID (default: "go-keychain")
- `--timeout duration` - Timeout for user presence confirmation (default: 30s)
- `--device string` - Specific device path to use (optional)
- `--user-verification` - Require user verification (PIN) (default: false)
- `--hex` - Output derived key in hex format instead of base64 (default: false)

**Examples:**

Basic authentication (with base64-encoded values):
```bash
go-keychain fido2 authenticate \
  --credential-id "pQECAyYgASFYIL8..." \
  --salt "rT8vN2kL..."
```

Authentication with hex output:
```bash
go-keychain fido2 authenticate \
  --credential-id "pQECAyYgASFYIL8..." \
  --salt "rT8vN2kL..." \
  --hex
```

Authentication requiring PIN:
```bash
go-keychain fido2 authenticate \
  --credential-id "pQECAyYgASFYIL8..." \
  --salt "rT8vN2kL..." \
  --user-verification
```

Authentication with hex-encoded input:
```bash
go-keychain fido2 authenticate \
  --credential-id "a1010226200121..." \
  --salt "ad3f2f37690b..."
```

**Output:**
```
Please touch your security key to authenticate...
Authentication successful
Derived Key (32 bytes): vT9kL3mN8pQ2rS5uV7wX0yZ1aB3cD4eF6gH8iJ9kL0mN2oP4qR6sT8uV0wX2yZ4=
```

**JSON Output:**
```bash
go-keychain fido2 authenticate \
  --credential-id "pQECAyYgASFYIL8..." \
  --salt "rT8vN2kL..." \
  --output json
```
```json
{
  "success": true,
  "derived_key": "vT9kL3mN8pQ2rS5uV7wX0yZ1aB3cD4eF6gH8iJ9kL0mN2oP4qR6sT8uV0wX2yZ4=",
  "key_length": 32
}
```

**Exit Codes:**
- `0` - Authentication successful
- `1` - Authentication failed (invalid credential, timeout, device error)

---

### fido2 info

Display detailed information about a connected FIDO2 security key.

**Usage:**
```bash
go-keychain fido2 info [flags]
```

**Flags:**
- `--device string` - Specific device path to query (defaults to first device found)

**Examples:**

Get info for first available device:
```bash
go-keychain fido2 info
```

Get info for specific device:
```bash
go-keychain fido2 info --device /dev/hidraw0
```

**Output:**
```
FIDO2 Device Information:
  Path:         /dev/hidraw0
  Vendor ID:    0x1050
  Product ID:   0x0407
  Manufacturer: Yubico
  Product:      YubiKey 5 NFC
  Serial:       12345678
  Transport:    usb
```

**JSON Output:**
```bash
go-keychain fido2 info --output json
```
```json
{
  "path": "/dev/hidraw0",
  "vendor_id": "0x1050",
  "product_id": "0x0407",
  "manufacturer": "Yubico",
  "product": "YubiKey 5 NFC",
  "serial_number": "12345678",
  "transport": "usb"
}
```

**Exit Codes:**
- `0` - Device info retrieved successfully
- `1` - No devices found or error

---

## Global Flags

All `fido2` commands support these global flags:

- `--output string` - Output format: `text` or `json` (default: "text")
- `--verbose` - Enable verbose output
- `--config string` - Config file path (default: ~/.go-keychain/config.yaml)

## Common Use Cases

### 1. Check for Security Key

Before performing operations, verify a security key is connected:

```bash
go-keychain fido2 list-devices
```

### 2. Interactive Registration Workflow

```bash
# Wait for key insertion
go-keychain fido2 wait-device

# Register new credential
go-keychain fido2 register myuser --rp-id myapp.example.com

# Save the credential_id and salt from output for later use
```

### 3. Script-Based Authentication

```bash
#!/bin/bash

CRED_ID="pQECAyYgASFYIL8..."
SALT="rT8vN2kL..."

# Authenticate and capture derived key
KEY=$(go-keychain fido2 authenticate \
  --credential-id "$CRED_ID" \
  --salt "$SALT" \
  --output json | jq -r '.derived_key')

# Use the key for encryption/decryption
echo "Derived key: $KEY"
```

### 4. Multi-Device Support

```bash
# List all devices
go-keychain fido2 list-devices --output json | jq -r '.devices[].path'

# Register with specific device
go-keychain fido2 register alice --device /dev/hidraw1

# Authenticate with specific device
go-keychain fido2 authenticate \
  --credential-id "$CRED_ID" \
  --salt "$SALT" \
  --device /dev/hidraw1
```

### 5. High-Security Setup with PIN

```bash
# Register with user verification (requires PIN-capable device)
go-keychain fido2 register alice \
  --user-verification \
  --rp-id secure.example.com

# Authenticate requiring PIN
go-keychain fido2 authenticate \
  --credential-id "$CRED_ID" \
  --salt "$SALT" \
  --user-verification
```

## Security Considerations

### Credential Storage

- **Credential ID and Salt**: Must be stored securely
- Consider using secure storage (OS keyring, encrypted database)
- Never commit these values to version control

### User Verification

- Use `--user-verification` flag for sensitive operations
- Requires PIN-capable security keys (e.g., YubiKey 5+, Nitrokey FIDO2)
- Provides additional security layer beyond physical presence

### Relying Party ID

- The `--rp-id` should match your application domain
- Must be consistent between registration and authentication
- Affects security scope of credentials

### Timeout Values

- Default 30s timeout provides good UX balance
- Reduce for automated systems: `--timeout 10s`
- Increase for accessibility: `--timeout 2m`

## Troubleshooting

### No Devices Found

**Symptoms:**
```
No FIDO2 devices found
```

**Solutions:**
1. Verify device is connected: `lsusb | grep -i yubikey`
2. Check permissions: `ls -l /dev/hidraw*`
3. Add udev rules (Linux):
   ```bash
   sudo usermod -aG plugdev $USER
   # See /usr/share/doc/yubikey-*/udev/
   ```
4. Ensure device supports FIDO2 (not just U2F)

### Permission Denied

**Symptoms:**
```
failed to open HID device /dev/hidraw0: permission denied
```

**Solutions:**
1. Linux: Add user to `plugdev` group
   ```bash
   sudo usermod -aG plugdev $USER
   newgrp plugdev
   ```
2. Create udev rule:
   ```bash
   # /etc/udev/rules.d/70-u2f.rules
   KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"
   ```
3. Reload udev rules:
   ```bash
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

### Timeout During Registration/Authentication

**Symptoms:**
```
failed to register credential: timeout waiting for user presence
```

**Solutions:**
1. Touch the security key when prompted
2. Increase timeout: `--timeout 60s`
3. Ensure device is not in use by another application
4. Check device LED indicators for status

### Invalid Credential

**Symptoms:**
```
authentication failed: invalid credential
```

**Solutions:**
1. Verify credential ID and salt are correct
2. Ensure credential was registered with same `--rp-id`
3. Check credential was not registered with different device
4. Confirm base64/hex encoding is correct

### User Verification Failed

**Symptoms:**
```
authentication failed: user verification required but not performed
```

**Solutions:**
1. Device may not support PIN
2. PIN may not be set on device
3. Set PIN using manufacturer's tools (e.g., `ykman fido access set-pin`)
4. Ensure `--user-verification` flag matches registration

## Device-Specific Notes

### YubiKey

- Models 5+ support FIDO2
- Models 4 support U2F only (not compatible)
- Configure using `ykman` tool
- Supports user verification (PIN)
- NFC models work over USB only for CLI

### Nitrokey

- Nitrokey FIDO2 fully supported
- Nitrokey FIDO U2F not compatible
- Configure using `nitropy` tool
- Supports user verification

### Feitian

- BioPass FIDO2 series supported
- May require firmware updates
- Check manufacturer website for latest drivers

### Google Titan

- Titan Security Key supported
- USB-A and USB-C variants both work
- Bluetooth variant not supported (HID only)

## Integration Examples

### Use FIDO2 for Encryption Key

```bash
#!/bin/bash
set -e

# Register once
REGISTRATION=$(go-keychain fido2 register myapp-encrypt \
  --rp-id myapp.local \
  --output json)

CRED_ID=$(echo "$REGISTRATION" | jq -r '.credential_id')
SALT=$(echo "$REGISTRATION" | jq -r '.salt')

# Save credentials
echo "$CRED_ID" > ~/.myapp/fido2-cred-id
echo "$SALT" > ~/.myapp/fido2-salt

# Later: Derive encryption key
KEY=$(go-keychain fido2 authenticate \
  --credential-id "$CRED_ID" \
  --salt "$SALT" \
  --output json \
  --hex | jq -r '.derived_key')

# Use key with OpenSSL
echo "secret data" | openssl enc -aes-256-cbc -K "$KEY" -iv "00000000000000000000000000000000"
```

### Automated Backup Decryption

```bash
#!/bin/bash
# Decrypt backup requiring FIDO2 authentication

CRED_ID=$(cat ~/.backup/fido2-cred-id)
SALT=$(cat ~/.backup/fido2-salt)

echo "Insert security key and touch when prompted..."

# Derive decryption key
KEY=$(go-keychain fido2 authenticate \
  --credential-id "$CRED_ID" \
  --salt "$SALT" \
  --timeout 60s \
  --hex | grep "Derived Key" | awk -F': ' '{print $2}')

# Decrypt backup
openssl enc -d -aes-256-cbc -K "$KEY" -iv "00000000000000000000000000000000" \
  -in backup.enc -out backup.tar.gz

echo "Backup decrypted successfully"
```

## See Also

- [WebAuthn Documentation](../webauthn.md)
- [Getting Started Guide](../getting-started.md)

## References

- [FIDO Alliance](https://fidoalliance.org/)
- [CTAP2 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
