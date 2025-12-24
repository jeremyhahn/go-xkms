# CanoKey CLI Usage

## PIV Operations

### Key Generation

```bash
# Generate ECDSA P-256 key
keychain key generate my-ecdsa-key \
  --backend canokey \
  --key-type ecdsa \
  --curve p256

# Generate RSA 2048 key
keychain key generate my-rsa-key \
  --backend canokey \
  --key-type rsa \
  --key-size 2048

# Generate in specific PIV slot
keychain key generate auth-key \
  --backend canokey \
  --key-type ecdsa \
  --curve p256 \
  --piv-slot 9a
```

### Key Operations

```bash
# List keys
keychain key list --backend canokey

# Get key info
keychain key info my-ecdsa-key --backend canokey

# Sign data
keychain key sign my-ecdsa-key \
  --backend canokey \
  --input message.txt \
  --output signature.bin

# Verify signature
keychain key verify my-ecdsa-key \
  --backend canokey \
  --input message.txt \
  --signature signature.bin

# Delete key
keychain key delete my-ecdsa-key --backend canokey
```

### Certificate Operations

```bash
# Create self-signed certificate
keychain cert create my-cert \
  --backend canokey \
  --key my-ecdsa-key \
  --cn "My Certificate" \
  --org "My Organization"

# Create CSR
keychain cert csr my-ecdsa-key \
  --backend canokey \
  --cn "My Certificate" \
  --org "My Organization" \
  --output csr.pem

# Import certificate
keychain cert import my-cert \
  --backend canokey \
  --file certificate.pem

# List certificates
keychain cert list --backend canokey
```

## FIDO2 Operations

### Device Management

```bash
# List connected FIDO2 devices
keychain fido2 list-devices

# Output:
# Device 1:
#   Path: /dev/hidraw3
#   Vendor ID: 0x20A0
#   Product ID: 0x42D4
#   Manufacturer: CanoKeys
#   Product: CanoKey Pigeon

# Wait for device connection
keychain fido2 wait-device --timeout 60s

# Get device info
keychain fido2 info
keychain fido2 info --device /dev/hidraw3
```

### Credential Registration

```bash
# Register new credential
keychain fido2 register alice \
  --rp-id example.com \
  --rp-name "Example App" \
  --display-name "Alice Smith"

# Output:
# Registration successful!
# Credential ID: base64-encoded-credential-id
# Salt: base64-encoded-salt
# Public Key: base64-encoded-public-key
# AAGUID: 01234567-89ab-cdef-0123-456789abcdef

# Register with user verification (PIN)
keychain fido2 register alice \
  --rp-id example.com \
  --user-verification

# Register with specific device
keychain fido2 register alice \
  --rp-id example.com \
  --device /dev/hidraw3
```

### Authentication

```bash
# Authenticate and derive key
keychain fido2 authenticate \
  --rp-id example.com \
  --credential-id <base64-credential-id> \
  --salt <base64-salt>

# Output:
# Derived Key: base64-encoded-key

# With hex output
keychain fido2 authenticate \
  --credential-id <credential-id> \
  --salt <salt> \
  --hex

# With user verification
keychain fido2 authenticate \
  --credential-id <credential-id> \
  --salt <salt> \
  --user-verification
```

## Multi-Protocol Access

### REST API

```bash
# Via REST endpoint
keychain key generate my-key \
  --server https://localhost:8443 \
  --backend canokey \
  --key-type ecdsa

keychain fido2 list-devices \
  --server https://localhost:8443
```

### gRPC

```bash
# Via gRPC endpoint
keychain key generate my-key \
  --server grpc://localhost:9443 \
  --backend canokey \
  --key-type ecdsa

keychain fido2 register alice \
  --server grpc://localhost:9443 \
  --rp-id example.com
```

### QUIC

```bash
# Via QUIC/HTTP3 endpoint
keychain key list \
  --server quic://localhost:8444 \
  --backend canokey

keychain fido2 authenticate \
  --server quic://localhost:8444 \
  --credential-id <id> \
  --salt <salt>
```

### Unix Socket

```bash
# Via Unix socket
keychain key generate my-key \
  --server unix:///var/run/keychain.sock \
  --backend canokey \
  --key-type ecdsa
```

## Output Formats

### JSON Output

```bash
# JSON format for scripting
keychain key list --backend canokey --output json

keychain fido2 list-devices --output json

keychain fido2 register alice --rp-id example.com --output json
```

### Table Output (Default)

```bash
# Human-readable tables
keychain key list --backend canokey

# Output:
# NAME         ALGORITHM  CREATED              SLOT
# my-ecdsa-key ECDSA      2024-01-15T10:30:00Z 9a
# my-rsa-key   RSA-2048   2024-01-15T10:35:00Z 9c
```

## Common Workflows

### TLS Client Certificate

```bash
# 1. Generate key
keychain key generate tls-client \
  --backend canokey \
  --key-type ecdsa \
  --curve p256 \
  --piv-slot 9a

# 2. Create CSR
keychain cert csr tls-client \
  --backend canokey \
  --cn "client.example.com" \
  --output client.csr

# 3. Get CA to sign, then import
keychain cert import tls-client-cert \
  --backend canokey \
  --file client.crt
```

### FIDO2 Passwordless Login

```bash
# 1. User enrolls their CanoKey
keychain fido2 register user123 \
  --rp-id myapp.example.com \
  --rp-name "My Application" \
  --display-name "John Doe"
# Save: credential-id, salt

# 2. Later, user authenticates
keychain fido2 authenticate \
  --rp-id myapp.example.com \
  --credential-id <saved-id> \
  --salt <saved-salt>
# Use derived key for session/encryption
```

### Hardware-Bound Encryption Key

```bash
# Register credential for encryption
keychain fido2 register encryption-key \
  --rp-id myapp.example.com

# Derive encryption key each time
KEY=$(keychain fido2 authenticate \
  --credential-id <id> \
  --salt <salt> \
  --hex)

# Use $KEY for AES-GCM encryption
```
