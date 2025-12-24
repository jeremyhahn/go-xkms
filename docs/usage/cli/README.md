# keychain CLI

The `keychain` command-line interface provides comprehensive cryptographic key management across multiple backends including software, hardware, and cloud-based key management systems.

## Overview

The CLI operates in two modes:

1. **Daemon Mode** (default): Communicates with the `keychaind` daemon via Unix socket, HTTP, gRPC, or QUIC
2. **Local Mode** (`--local`): Bypasses the daemon and accesses backends directly

## Installation

### Building from Source

```bash
# Build CLI with default backends (software)
make cli

# Build with specific backends
make cli WITH_PKCS8=1 WITH_FROST=1

# Build with all backends
make cli-all

# Install to system
sudo make install-cli
```

The binary will be available at `build/bin/keychain`.

### Build Tags

The following optional features can be enabled at build time:

- `pkcs8` - PKCS#8 software backend (enabled by default)
- `pkcs11` - PKCS#11 HSM backend (requires CGO)
- `tpm2` - TPM 2.0 hardware backend
- `awskms` - AWS Key Management Service
- `gcpkms` - Google Cloud KMS
- `azurekv` - Azure Key Vault
- `vault` - HashiCorp Vault
- `frost` - FROST threshold signatures (enabled by default)
- `quantum` - Post-quantum cryptography (requires liboqs)

## Global Flags

These flags are available for all commands:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--config` | | string | `$HOME/.keychain.yaml` | Configuration file path |
| `--backend` | | string | `software` | Backend to use: software, pkcs11, tpm2, awskms, gcpkms, azurekv, vault |
| `--key-dir` | | string | `keychain-data/keys` | Key storage directory (for file-based backends) |
| `--output` | `-o` | string | `text` | Output format: text, json, table |
| `--verbose` | `-v` | bool | `false` | Enable verbose output |
| `--local` | `-l` | bool | `false` | Use local backend directly (bypass keychaind daemon) |
| `--server` | `-s` | string | `keychain-data/keychain.sock` | Keychain server URL |
| `--tls-insecure` | | bool | `false` | Skip TLS certificate verification (not recommended) |
| `--tls-cert` | | string | | Client certificate file for mTLS authentication |
| `--tls-key` | | string | | Client key file for mTLS authentication |
| `--tls-ca` | | string | | CA certificate file for server verification |
| `--token` | | string | | JWT authentication token (use 'user login' to obtain) |

### Server URL Formats

The `--server` flag supports multiple connection types:

```bash
# Unix socket (default)
--server unix:///path/to/socket.sock

# HTTP REST
--server http://localhost:8080
--server https://keychain.example.com

# gRPC
--server grpc://localhost:9090
--server grpcs://keychain.example.com:9090

# QUIC/HTTP3
--server quic://keychain.example.com:443
```

## Command Groups

### version - Print version information

Display version, build information, and runtime details.

```bash
keychain version
keychain version -o json
```

[Documentation](./version.md)

---

### backends - Manage backends

List and inspect available cryptographic backends.

**Subcommands:**
- `list` - List all available backends
- `info <backend>` - Show detailed information about a specific backend

```bash
keychain backends list
keychain backends info software
keychain backends info pkcs11
```

[Documentation](./backends.md)

---

### key - Key management

Comprehensive key lifecycle management including generation, rotation, import, export, signing, encryption, and more.

**Subcommands:**
- `generate <key-id>` - Generate a new key
- `list` - List all keys
- `get <key-id>` - Get key details
- `delete <key-id>` - Delete a key
- `sign <key-id> <data>` - Sign data
- `verify <key-id> <data> <signature>` - Verify signature
- `rotate <key-id>` - Rotate a key
- `encrypt <key-id> <plaintext>` - Symmetric encryption
- `decrypt <key-id> <ciphertext>` - Symmetric decryption
- `encrypt-asym <key-id> <plaintext>` - Asymmetric encryption
- `import <key-id> <wrapped-key-file>` - Import wrapped key
- `export <key-id> <output-file>` - Export key (wrapped)
- `copy <key-id> <dest-key-id>` - Copy key to new ID
- `get-import-params <key-id>` - Get key import parameters
- `wrap <key-material-file> <params-file> <output-file>` - Wrap key material
- `unwrap <wrapped-key-file> <params-file> <output-file>` - Unwrap key material

```bash
keychain key generate my-signing-key --key-type signing --algorithm ed25519
keychain key list --backend software
keychain key sign my-signing-key "message to sign"
keychain key rotate my-signing-key
```

[Documentation](./key.md)

---

### cert - Certificate management

Manage X.509 certificates and certificate chains.

**Subcommands:**
- `save <key-id> <cert-file>` - Save certificate for a key
- `get <key-id>` - Get certificate
- `delete <key-id>` - Delete certificate
- `list` - List all certificates
- `exists <key-id>` - Check if certificate exists
- `save-chain <key-id> <cert-file>...` - Save certificate chain
- `get-chain <key-id>` - Get certificate chain
- `generate-ca` - Generate Certificate Authority
- `issue` - Issue certificate

```bash
keychain cert generate-ca --cn "My CA" --key-id my-ca
keychain cert issue --issuer my-ca --cn "server.example.com" --key-id server-cert
keychain cert get my-ca
keychain cert save-chain server-cert cert.pem intermediate.pem
```

[Documentation](./cert.md)

---

### tls - TLS operations

Manage TLS certificates and configurations.

**Subcommands:**
- `get <key-id>` - Get TLS certificate and key

```bash
keychain tls get my-tls-cert
```

[Documentation](./tls.md)

---

### fido2 - FIDO2 security keys

WebAuthn/FIDO2 security key operations for passwordless authentication.

**Subcommands:**
- `list-devices` - List FIDO2 devices
- `wait-device` - Wait for device to be connected
- `register <username>` - Register new credential
- `authenticate` - Authenticate with credential
- `info` - Show FIDO2 device information

```bash
keychain fido2 list-devices
keychain fido2 register alice
keychain fido2 authenticate --username alice
```

[Documentation](./fido2.md)

---

### admin - Administrator management

Manage administrator accounts and permissions.

**Subcommands:**
- `create <username>` - Create new administrator
- `list` - List administrators
- `get <username>` - Get administrator details
- `delete <username>` - Delete administrator
- `disable <username>` - Disable administrator account
- `enable <username>` - Enable administrator account
- `status` - Show current administrator status

```bash
keychain admin create bob --password secretpass
keychain admin list
keychain admin disable bob
```

[Documentation](./admin.md)

---

### user - User management

Manage user accounts and authentication.

**Subcommands:**
- `register <username>` - Register new user
- `login` - User login (obtain JWT token)
- `list` - List users
- `get <username>` - Get user details
- `delete <username>` - Delete user
- `disable <username>` - Disable user account
- `enable <username>` - Enable user account
- `status` - Show current user status
- `credentials <username>` - Manage user credentials

```bash
keychain user register alice
keychain user login --username alice
keychain user list
keychain user credentials alice
```

[Documentation](./user.md)

---

### migrate - Key migration

Migrate cryptographic keys between backends with validation and verification.

**Subcommands:**
- `plan --from <source> --to <dest>` - Show migration plan
- `execute --from <source> --to <dest>` - Execute migration
- `validate --key-id <key-id>` - Validate migrated key

```bash
# Plan migration from software to HSM
keychain migrate plan --from software --to pkcs11

# Execute migration with filters
keychain migrate execute \
  --from software \
  --to pkcs11 \
  --key-types signing \
  --parallel 4

# Validate migrated key
keychain migrate validate \
  --key-id my-key \
  --from software \
  --to pkcs11
```

[Documentation](./migrate.md)

---

### frost - Threshold signatures (requires `frost` build tag)

FROST (Flexible Round-Optimized Schnorr Threshold) signature operations for M-of-N threshold signing.

**Subcommands:**
- `keygen` - Generate FROST key packages (trusted dealer)
- `import` - Import FROST key package
- `list` - List FROST keys
- `info <key-id>` - Show FROST key details
- `delete <key-id>` - Delete FROST key
- `round1` - Generate nonces and commitments (Round 1)
- `round2` - Generate signature share (Round 2)
- `aggregate` - Aggregate signature shares
- `verify` - Verify FROST signature

**Supported Algorithms:**
- `FROST-Ed25519-SHA512` (default, recommended)
- `FROST-ristretto255-SHA512`
- `FROST-Ed448-SHAKE256`
- `FROST-P256-SHA256` (FIPS compliant)
- `FROST-secp256k1-SHA256` (blockchain compatible)

```bash
# Dealer mode: generate and export all packages
keychain frost keygen \
  --key-id mykey \
  --threshold 2 \
  --total 3 \
  --export-dir ./packages

# Participant imports their package
keychain frost import --package ./packages/participant_1.json

# Round 1: Generate commitments
keychain frost round1 --key-id mykey --output commitment.json

# Round 2: Generate signature share
keychain frost round2 \
  --key-id mykey \
  --message "sign this" \
  --nonces commitment.json.nonces \
  --commitments p1.json,p2.json,p3.json \
  --output share.json

# Aggregate signatures
keychain frost aggregate \
  --key-id mykey \
  --message "sign this" \
  --commitments p1.json,p2.json \
  --shares share1.json,share2.json \
  --output signature.bin
```

[Documentation](./frost.md)

---

### dkek - DKEK operations (requires `pkcs11` build tag)

Device Key Encryption Key operations for SmartCard-HSM using Shamir's Secret Sharing.

**Subcommands:**
- `generate` - Generate DKEK shares
- `list` - List available DKEK shares
- `verify` - Verify DKEK shares integrity
- `delete [share-index]` - Delete DKEK share(s)

```bash
# Generate DKEK with 5 shares, threshold of 3
keychain dkek generate --shares 5 --threshold 3 --backend pkcs11

# List shares
keychain dkek list --backend pkcs11

# Verify shares
keychain dkek verify --backend pkcs11

# Delete specific share
keychain dkek delete 1 --backend pkcs11

# Delete all shares
keychain dkek delete --all --backend pkcs11
```

[Documentation](./dkek.md)

---

## Common Workflows

### Local Key Generation and Signing

```bash
# Generate a signing key locally
keychain --local key generate my-key \
  --key-type signing \
  --algorithm ed25519

# Sign data
keychain --local key sign my-key "message to sign" \
  --output signature.bin

# Verify signature
keychain --local key verify my-key \
  "message to sign" \
  signature.bin
```

### Remote Server Access with TLS

```bash
# Login to get JWT token
keychain --server https://keychain.example.com \
  --tls-ca ca.pem \
  user login --username alice

# Use token for subsequent commands
keychain --server https://keychain.example.com \
  --tls-ca ca.pem \
  --token <jwt-token> \
  key list
```

### HSM Key Operations

```bash
# Generate key in PKCS#11 HSM
keychain --backend pkcs11 key generate hsm-key \
  --key-type signing \
  --algorithm rsa \
  --key-size 4096

# Sign with HSM key
keychain --backend pkcs11 key sign hsm-key document.pdf
```

### Multi-Backend Migration

```bash
# Migrate all signing keys from software to TPM
keychain migrate execute \
  --from software \
  --to tpm2 \
  --key-types signing \
  --delete-source \
  --parallel 8 \
  --force
```

## Configuration File

The CLI supports YAML configuration files to avoid repetitive flags:

**Location:** `$HOME/.keychain.yaml` (default) or specify with `--config`

```yaml
# Backend configuration
backend: software
key_dir: /var/lib/keychain/keys

# Server connection
server: unix:///var/run/keychain.sock
# server: https://keychain.example.com:8443

# TLS configuration
tls:
  ca_cert: /etc/keychain/ca.pem
  client_cert: /etc/keychain/client.pem
  client_key: /etc/keychain/client-key.pem
  insecure: false

# Output preferences
output_format: json
verbose: false

# Authentication
# token: <jwt-token>  # Or use 'user login' to obtain

# Backend-specific configuration
backends:
  pkcs11:
    library: /usr/lib/softhsm/libsofthsm2.so
    slot: 0
    pin: 1234

  tpm2:
    device: /dev/tpmrm0

  awskms:
    region: us-west-2

  gcpkms:
    project: my-project
    location: global

  azurekv:
    vault_url: https://myvault.vault.azure.net
```

## Output Formats

All commands support multiple output formats via `--output` or `-o`:

### Text Format (default)

Human-readable output:
```bash
$ keychain key list
KEY ID              ALGORITHM    TYPE        CREATED
my-key              Ed25519      signing     2025-01-15T10:30:00Z
encryption-key      AES-256-GCM  encryption  2025-01-15T11:00:00Z
```

### JSON Format

Machine-parsable structured output:
```bash
$ keychain key list -o json
{
  "keys": [
    {
      "cn": "my-key",
      "algorithm": "Ed25519",
      "key_type": "signing",
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

### Table Format

Formatted table output:
```bash
$ keychain key list -o table
┌─────────────────┬─────────────┬────────────┬──────────────────────┐
│ KEY ID          │ ALGORITHM   │ TYPE       │ CREATED              │
├─────────────────┼─────────────┼────────────┼──────────────────────┤
│ my-key          │ Ed25519     │ signing    │ 2025-01-15T10:30:00Z │
│ encryption-key  │ AES-256-GCM │ encryption │ 2025-01-15T11:00:00Z │
└─────────────────┴─────────────┴────────────┴──────────────────────┘
```

## Error Handling

The CLI returns appropriate exit codes:

- `0` - Success
- `1` - General error
- Authentication errors, connection failures, and validation errors are reported with descriptive messages

Enable verbose output with `-v` for debugging:

```bash
keychain -v key generate test-key
[VERBOSE] Creating backend: software
[VERBOSE] Generating key: test-key
[VERBOSE] Key type: signing
[VERBOSE] Algorithm: Ed25519
Successfully generated key: test-key
```

## Environment Variables

The following environment variables can be used instead of flags:

- `KEYCHAIN_CONFIG` - Configuration file path
- `KEYCHAIN_BACKEND` - Default backend
- `KEYCHAIN_SERVER` - Server URL
- `KEYCHAIN_TOKEN` - JWT authentication token

Example:
```bash
export KEYCHAIN_BACKEND=pkcs11
export KEYCHAIN_SERVER=https://keychain.example.com
keychain key list
```

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
keychain completion bash > /etc/bash_completion.d/keychain

# Zsh
keychain completion zsh > ~/.zsh/completion/_keychain

# Fish
keychain completion fish > ~/.config/fish/completions/keychain.fish

# PowerShell
keychain completion powershell > keychain.ps1
```

## See Also

- [Getting Started Guide](../getting-started.md)
- [Key Import/Export](../key-import-export.md)
- [Key Migration](../key-migration.md)
- [Certificate Management](../certificate-management.md)
- [User Management](../user.md)
- [WebAuthn/FIDO2](../webauthn.md)

## Support

For issues, feature requests, or contributions:
- GitHub: https://github.com/jeremyhahn/go-keychain
- Documentation: https://github.com/jeremyhahn/go-keychain/tree/main/docs

## License

go-keychain is dual-licensed under AGPL-3.0 and commercial license.
See LICENSE file for details or contact licensing@automatethethings.com for commercial licensing.
