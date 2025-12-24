# TLS CLI Command

The `tls` command provides operations for retrieving TLS certificates with their associated private keys and certificate chains.

## Overview

The TLS command helps you:
- Retrieve combined TLS certificates (private key + X.509 certificate)
- Get certificate chains for complete TLS configuration
- Export certificates in various formats
- Verify certificate details and validity

## Available Commands

### tls get

Retrieve a complete TLS certificate including the private key, X.509 certificate, and optional certificate chain.

```bash
keychain tls get <key-id> [flags]
```

**Arguments:**
- `<key-id>` - Identifier of the TLS key/certificate to retrieve (required)

**Flags:**
- `--key-type <type>` - Key type (default: "tls")
- `--key-algorithm <algorithm>` - Key algorithm: rsa, ecdsa (default: "rsa")
- `--key-size <bits>` - Key size in bits for RSA (default: 2048)
- `--curve <curve>` - Elliptic curve for ECDSA: P-256, P-384, P-521 (default: "P-256")

## Examples

### Basic Usage

```bash
# Get TLS certificate with default settings (RSA 2048)
keychain tls get web-server

# Get TLS certificate with explicit algorithm
keychain tls get api-server --key-algorithm rsa --key-size 4096
```

### ECDSA Certificates

```bash
# Get ECDSA certificate with P-256 curve
keychain tls get edge-device --key-algorithm ecdsa --curve P-256

# Get ECDSA certificate with P-384 curve
keychain tls get secure-api --key-algorithm ecdsa --curve P-384

# Get ECDSA certificate with P-521 curve
keychain tls get high-security --key-algorithm ecdsa --curve P-521
```

### RSA Certificates

```bash
# Get RSA certificate with 2048-bit key (default)
keychain tls get app-server --key-algorithm rsa --key-size 2048

# Get RSA certificate with 3072-bit key
keychain tls get legacy-app --key-algorithm rsa --key-size 3072

# Get RSA certificate with 4096-bit key
keychain tls get critical-system --key-algorithm rsa --key-size 4096
```

### JSON Output

```bash
# Get certificate details in JSON format
keychain --output json tls get web-server
```

**JSON Output Example:**
```json
{
  "certificate": {
    "subject": "CN=web-server.example.com",
    "issuer": "CN=Example CA",
    "serial_number": "123456789",
    "not_before": "2025-01-01 00:00:00 +0000 UTC",
    "not_after": "2026-01-01 00:00:00 +0000 UTC",
    "dns_names": ["web-server.example.com", "www.example.com"],
    "key_algorithm": "RSA",
    "key_size": 2048
  },
  "chain_length": 2,
  "has_private_key": true
}
```

### Text Output

```bash
# Get certificate in human-readable format (default)
keychain tls get web-server
```

**Text Output Example:**
```
TLS Certificate: web-server

Certificate Details:
  Subject: CN=web-server.example.com
  Issuer: CN=Example CA
  Serial Number: 123456789
  Valid From: 2025-01-01 00:00:00 +0000 UTC
  Valid Until: 2026-01-01 00:00:00 +0000 UTC
  DNS Names:
    - web-server.example.com
    - www.example.com
  Key Algorithm: RSA
  Key Size: 2048

Certificate Chain: 2 certificates
Private Key: Available
```

## Output Formats

The `tls get` command supports multiple output formats controlled by the global `--output` flag:

### Text Format (Default)

Human-readable format with all certificate details:

```bash
keychain tls get web-server
# or explicitly
keychain --output text tls get web-server
```

### JSON Format

Structured JSON output for programmatic use:

```bash
keychain --output json tls get web-server | jq .
```

### PEM Format

For PEM-encoded certificate and key export (when supported):

```bash
keychain tls get web-server > server.pem
```

## Key Algorithms

### RSA

RSA certificates support the following key sizes:

| Key Size | Security Level | Use Case |
|----------|----------------|----------|
| 2048 | Standard | General web servers, APIs |
| 3072 | Enhanced | Compliance requirements |
| 4096 | High | Long-term certificates, critical systems |

**Example:**
```bash
keychain tls get web-server --key-algorithm rsa --key-size 2048
```

### ECDSA

ECDSA certificates support the following curves:

| Curve | Security Level | Key Size Equivalent | Use Case |
|-------|----------------|---------------------|----------|
| P-256 | 128-bit | RSA 3072 | Modern web servers, IoT |
| P-384 | 192-bit | RSA 7680 | High-security applications |
| P-521 | 256-bit | RSA 15360 | Maximum security |

**Example:**
```bash
keychain tls get secure-api --key-algorithm ecdsa --curve P-256
```

## Certificate Components

The `tls get` command retrieves three components:

### Private Key

The private key associated with the certificate. The key remains protected by the backend's security mechanisms and is retrieved securely.

**Security Notes:**
- Hardware backends (TPM2, PKCS#11) do not export the raw private key
- Software backends (PKCS#8) encrypt the private key
- Cloud backends (AWS KMS, GCP KMS) provide key references only

### X.509 Certificate

The leaf certificate containing:
- Public key
- Subject (certificate identity)
- Issuer (who signed the certificate)
- Validity period
- DNS names (Subject Alternative Names)
- Key usage and extended key usage

### Certificate Chain

Optional chain of intermediate and root certificates:
- Intermediate CA certificates
- Root CA certificate (if available)
- Used for complete TLS handshake verification

**Note:** If the certificate chain is not found, only the leaf certificate is returned. This is normal for self-signed certificates.

## Backend Integration

The TLS command integrates with the configured backend for secure key and certificate retrieval.

### Software Backends

```bash
# Use PKCS#8 backend (default)
keychain --backend pkcs8 tls get web-server
```

### Hardware Backends

```bash
# Use TPM2 backend for hardware-backed keys
keychain --backend tpm2 tls get edge-device --key-algorithm ecdsa --curve P-256

# Use PKCS#11 HSM
keychain --backend pkcs11 tls get secure-server --key-algorithm rsa --key-size 4096
```

### Cloud Backends

```bash
# Use AWS KMS
keychain --backend awskms tls get cloud-app

# Use GCP KMS
keychain --backend gcpkms tls get gcp-service

# Use Azure Key Vault
keychain --backend azurekv tls get azure-app
```

## Use Cases

### Web Server Configuration

```bash
# Get certificate for nginx/apache
keychain tls get web-server > /etc/ssl/certs/server.pem

# Get certificate with intermediate chain
keychain tls get web-server --key-algorithm rsa --key-size 2048
```

### API Server

```bash
# Get ECDSA certificate for modern API server
keychain tls get api-server --key-algorithm ecdsa --curve P-256

# Verify certificate details
keychain --output json tls get api-server | jq '.certificate'
```

### Load Balancer

```bash
# Get certificate for load balancer
keychain tls get lb-frontend --key-algorithm rsa --key-size 2048
```

### Microservices

```bash
# Get certificates for internal mTLS
keychain tls get service-a --key-algorithm ecdsa --curve P-256
keychain tls get service-b --key-algorithm ecdsa --curve P-256
```

### Edge Devices

```bash
# Get ECDSA certificate for IoT device (smaller, faster)
keychain tls get iot-gateway --key-algorithm ecdsa --curve P-256
```

## Certificate Verification

Verify certificate details before deployment:

```bash
# Check certificate validity period
keychain --output json tls get web-server | jq '.certificate | {not_before, not_after}'

# Verify DNS names
keychain --output json tls get web-server | jq '.certificate.dns_names'

# Check key algorithm and size
keychain --output json tls get web-server | jq '.certificate | {key_algorithm, key_size}'
```

## Global Flags

All TLS commands support these global flags:

```bash
--output <format>     Output format: text, json (default: text)
--config <path>       Configuration file path
--backend <name>      Backend to use: pkcs8, tpm2, pkcs11, etc.
--verbose             Enable verbose logging
```

## Verbose Output

Enable verbose logging to see detailed operations:

```bash
keychain --verbose tls get web-server
```

**Verbose Output Example:**
```
Getting TLS certificate for key: web-server
Key algorithm: rsa
Certificate Subject: CN=web-server.example.com
Certificate chain length: 2

TLS Certificate: web-server
[... certificate details ...]
```

## Error Handling

### Key Not Found

```bash
keychain tls get missing-server
# Error: failed to get key: key not found: missing-server
```

**Solution:** Verify the key ID exists:
```bash
keychain keys list
```

### Certificate Not Found

```bash
keychain tls get server-without-cert
# Error: failed to get certificate: certificate not found: server-without-cert
```

**Solution:** Generate a certificate for the key:
```bash
keychain cert create server-without-cert
```

### Backend Connection Failed

```bash
keychain --backend awskms tls get web-server
# Error: failed to create backend: unable to connect to AWS KMS
```

**Solution:** Check backend configuration and credentials:
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check backend info
keychain backends info awskms
```

### Invalid Key Parameters

```bash
keychain tls get web-server --key-algorithm invalid
# Error: invalid key parameters: unsupported algorithm: invalid
```

**Solution:** Use valid algorithms (rsa, ecdsa) and parameters.

## Best Practices

### Algorithm Selection

```bash
# Modern deployments: Use ECDSA P-256 (faster, smaller)
keychain tls get modern-app --key-algorithm ecdsa --curve P-256

# Legacy compatibility: Use RSA 2048
keychain tls get legacy-app --key-algorithm rsa --key-size 2048

# High security: Use ECDSA P-384 or RSA 4096
keychain tls get critical-app --key-algorithm ecdsa --curve P-384
```

### Certificate Rotation

```bash
# Generate new certificate
keychain cert create web-server-new --key-algorithm ecdsa --curve P-256

# Retrieve and deploy new certificate
keychain tls get web-server-new

# After grace period, rotate to new certificate
keychain cert rotate web-server web-server-new
```

### Backup and Disaster Recovery

```bash
# Export certificates for backup (software backends only)
keychain tls get web-server > backup/web-server.pem

# For hardware backends, maintain certificate copies in cert storage
keychain cert export web-server > backup/web-server-cert.pem
```

## Troubleshooting

### Certificate Chain Not Found

This is normal for self-signed certificates:

```bash
keychain --verbose tls get self-signed
# Certificate chain not found (this is OK): chain not found
```

No action needed unless you require intermediate certificates.

### Permission Denied

```bash
keychain tls get web-server
# Error: failed to get key: permission denied
```

**Solution:** Check backend permissions and authentication:
```bash
# For PKCS#11, verify PIN
keychain --backend pkcs11 --pin "$HSM_PIN" tls get web-server

# For cloud backends, verify IAM/RBAC permissions
```

### Wrong Key Type

```bash
keychain tls get signing-key
# Warning: Key type mismatch (expected: tls, got: signing)
```

**Solution:** Use the correct key type flag or verify key purpose.

## See Also

- [Certificate Management](../certificate-management.md) - Certificate creation and management
- [Key Management](./key.md) - Key generation and operations
- [Backends Command](backends.md) - Backend discovery and capabilities
- [Getting Started](../getting-started.md) - Initial setup and configuration
