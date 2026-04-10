# Backends CLI Command

The `backends` command provides tools to discover and inspect available cryptographic backends in your go-xkms installation.

## Overview

The backends command helps you:
- List all available cryptographic backends
- View detailed capabilities of each backend
- Verify which backends are enabled in your build
- Understand backend features before configuration

## Available Commands

### backends list

Lists all cryptographic backends available in the current build.

```bash
xkmsctl backends list
```

**Output (text format):**
```
Available Backends:
  - software
  - pkcs11
  - tpm2
  - awskms
  - gcpkms
  - azurekv
  - vault
```

**Output (JSON format):**
```bash
xkmsctl --output json backends list
```

```json
{
  "backends": [
    "software",
    "pkcs11",
    "tpm2",
    "awskms",
    "gcpkms",
    "azurekv",
    "vault"
  ]
}
```

### backends info

Display detailed information and capabilities for a specific backend.

```bash
xkmsctl backends info <backend-name>
```

**Arguments:**
- `<backend-name>` - Name of the backend to inspect (required)

**Examples:**

```bash
# Get information about the software backend
xkmsctl backends info software

# Get TPM2 backend capabilities
xkmsctl backends info tpm2

# View AWS KMS backend details
xkmsctl backends info awskms
```

**Output (text format):**
```
Backend: software
Capabilities:
  Keys: true
  Hardware-backed: false
  Signing: true
  Decryption: true
  Key Rotation: true
  Symmetric Encryption: true
  Import: true
  Export: true
  Key Agreement: true
  ECIES: true
```

**Output (JSON format):**
```bash
xkmsctl --output json backends info software
```

```json
{
  "backend": "software",
  "capabilities": {
    "keys": true,
    "hardware_backed": false,
    "signing": true,
    "decryption": true,
    "key_rotation": true,
    "symmetric_encryption": true,
    "import": true,
    "export": true,
    "key_agreement": true,
    "ecies": true
  }
}
```

## Backend Types

### Software Backends

**software**
- Software-based key storage using PKCS#8 encrypted key files
- No hardware protection
- Full feature support including ECIES and key agreement
- Best for: Development, testing, and offline use

### Hardware Backends

**pkcs11**
- PKCS#11 interface for HSMs and smart cards
- Hardware-backed security
- No key rotation support
- Best for: Enterprise PKI, compliance requirements

**tpm2**
- TPM 2.0 hardware security module
- Hardware-backed security
- No key rotation support
- Best for: Edge devices, IoT, on-premise servers

### Cloud Backends

**awskms**
- AWS Key Management Service
- Cloud HSM-backed
- Supports key rotation
- Best for: AWS-hosted applications

**gcpkms**
- Google Cloud Key Management Service
- Cloud HSM-backed (FIPS 140-2 Level 3)
- Supports key rotation
- Best for: GCP-hosted applications

**azurekv**
- Azure Key Vault
- Cloud HSM-backed
- Supports key rotation
- Best for: Azure-hosted applications

**vault**
- HashiCorp Vault
- Software or hardware-backed (depending on configuration)
- Supports key rotation
- Best for: Multi-cloud, hybrid deployments

## Backend Capabilities

The `backends info` command shows these capabilities for each backend:

| Capability | Description |
|------------|-------------|
| Keys | Can store and manage cryptographic keys |
| Hardware-backed | Keys are protected by hardware security module |
| Signing | Can perform digital signature operations |
| Decryption | Can decrypt encrypted data |
| Key Rotation | Supports automated key rotation |
| Symmetric Encryption | Supports AES-GCM symmetric encryption |
| Import | Can import existing keys |
| Export | Can export keys (non-hardware backends only) |
| Key Agreement | Supports ECDH key agreement protocols |
| ECIES | Supports Elliptic Curve Integrated Encryption Scheme |

## Usage Modes

The backends commands support both local and remote modes:

### Local Mode

Directly queries backend information without connecting to xkmsd server:

```bash
xkmsctl backends list
xkmsctl backends info software
```

### Remote Mode

Queries backend information from a running xkmsd server:

```bash
# Connect to remote server and list backends
xkmsctl --server-url https://xkms.example.com:8443 backends list

# Get backend info from remote server
xkmsctl --server-url https://xkms.example.com:8443 backends info tpm2
```

## Global Flags

All backends commands support these global flags:

```bash
--output <format>     Output format: text, json, table (default: text)
--config <path>       Configuration file path
--server-url <url>    Remote xkmsd server URL
--verbose             Enable verbose logging
```

## Examples

### Discover Available Backends

```bash
# List backends in your build
xkmsctl backends list

# Check if TPM2 is available
xkmsctl backends list | grep tpm2
```

### Compare Backend Features

```bash
# Compare software vs hardware capabilities
xkmsctl backends info software
xkmsctl backends info tpm2

# View cloud backend features
xkmsctl backends info awskms
xkmsctl backends info gcpkms
xkmsctl backends info azurekv
```

### Verify Build Configuration

```bash
# Check if required backends are available
xkmsctl backends list

# Verify PKCS#11 support before configuration
xkmsctl backends info pkcs11
```

### Remote Backend Discovery

```bash
# Discover backends available on production server
xkmsctl --server-url https://prod.example.com:8443 backends list

# Check staging server capabilities
xkmsctl --server-url https://staging.example.com:8443 backends info vault
```

## Build Tags

Backend availability depends on build tags used during compilation. See the [Build Configuration](../getting-started.md#build-configuration) guide for details on enabling specific backends.

### Default Build
```bash
# Software backend is enabled by default
make build
xkmsctl backends list  # Shows: software
```

### Custom Build
```bash
# Build with all backends
make build WITH_PKCS11=1 WITH_TPM2=1 WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1 WITH_VAULT=1

# Verify all backends are available
xkmsctl backends list
```

## Troubleshooting

### Backend Not Listed

If an expected backend is missing:

1. Check your build configuration:
   ```bash
   xkmsctl version  # Shows build information
   xkmsctl backends list
   ```

2. Rebuild with required backend:
   ```bash
   make build WITH_TPM2=1  # Example: enable TPM2
   ```

3. Verify build tags:
   ```bash
   go build -tags "software tpm2" ./...
   ```

### Remote Server Connection Failed

If backend commands fail in remote mode:

```bash
# Verify server is running
curl -k https://xkms.example.com:8443/health

# Check TLS configuration
xkmsctl --server-url https://xkms.example.com:8443 \
  --tls-ca /path/to/ca.pem \
  backends list

# Enable verbose logging
xkmsctl --verbose \
  --server-url https://xkms.example.com:8443 \
  backends list
```

### Hardware Backend Not Working

For hardware backends (pkcs11, tpm2):

```bash
# Check if hardware is available
ls -l /dev/tpmrm0  # TPM2
ls -l /usr/lib/softhsm/libsofthsm2.so  # SoftHSM

# View backend capabilities
xkmsctl backends info tpm2
xkmsctl backends info pkcs11

# Test with verbose logging
xkmsctl --verbose backends info tpm2
```

## See Also

- [Getting Started Guide](../getting-started.md) - Backend selection and configuration
- [Software Backend](../../backends/software.md) - Software backend documentation
- [TPM2 Backend](../../backends/tpm2.md) - Hardware TPM documentation
- [PKCS#11 Backend](../../backends/pkcs11.md) - HSM integration
- [AWS KMS Backend](../../backends/awskms.md) - Cloud backend configuration
- [Build System](../../configuration/build-system.md) - Build tags and compilation
