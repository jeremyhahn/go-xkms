# xkmsctl CLI

The `xkmsctl` command-line interface provides comprehensive cryptographic key management across multiple backends including software, hardware, and cloud-based key management systems.

## Overview

The CLI operates in two modes:

1. **Daemon Mode** (default): Communicates with the `xkmsd` daemon via Unix socket, HTTP, gRPC, or QUIC
2. **Local Mode** (`--local`): Bypasses the daemon and accesses backends directly

## Installation

### Building from Source

```bash
# Build CLI with default backends (software)
make cli

# Build with specific backends
make cli WITH_SOFTWARE=1 WITH_FROST=1

# Build with all backends
make cli-all

# Install to system
sudo make install-cli
```

The binary will be available at `build/bin/xkmsctl`.

### Build Tags

The following optional features can be enabled at build time:

- `software` - Software backend with PKCS#8 key storage (enabled by default)
- `pkcs11` - PKCS#11 HSM backend (requires CGO)
- `tpm2` - TPM 2.0 hardware backend
- `awskms` - AWS Key Management Service
- `gcpkms` - Google Cloud KMS
- `azurekv` - Azure Key Vault
- `vault` - HashiCorp Vault
- `frost` - FROST threshold signatures (enabled by default)
- `quantum` - Post-quantum cryptography (pure Go, always available)

## Global Flags

These flags are available for all commands:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--config` | | string | `$HOME/.xkms.yaml` | Configuration file path |
| `--backend` | | string | `software` | Backend to use: software, pkcs11, tpm2, awskms, gcpkms, azurekv, vault |
| `--key-dir` | | string | `xkms-data/keys` | Key storage directory (for file-based backends) |
| `--output` | `-o` | string | `text` | Output format: text, json, table |
| `--verbose` | `-v` | bool | `false` | Enable verbose output |
| `--local` | `-l` | bool | `false` | Use local backend directly (bypass xkmsd daemon) |
| `--server` | `-s` | string | `xkms-data/xkms.sock` | xKMS server URL |
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
--server https://xkms.example.com

# gRPC
--server grpc://localhost:9090
--server grpcs://xkms.example.com:9090

# QUIC/HTTP3
--server quic://xkms.example.com:443
```

## Command Groups

### version - Print version information

Display version, build information, and runtime details.

```bash
xkmsctl version
xkmsctl version -o json
```

[Documentation](./version.md)

---

### backends - Manage backends

List and inspect available cryptographic backends.

**Subcommands:**
- `list` - List all available backends
- `info <backend>` - Show detailed information about a specific backend

```bash
xkmsctl backends list
xkmsctl backends info software
xkmsctl backends info pkcs11
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
xkmsctl key generate my-signing-key --key-type signing --algorithm ed25519
xkmsctl key list --backend software
xkmsctl key sign my-signing-key "message to sign"
xkmsctl key rotate my-signing-key
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
xkmsctl cert generate-ca --cn "My CA" --key-id my-ca
xkmsctl cert issue --issuer my-ca --cn "server.example.com" --key-id server-cert
xkmsctl cert get my-ca
xkmsctl cert save-chain server-cert cert.pem intermediate.pem
```

[Documentation](./cert.md)

---

### tls - TLS operations

Manage TLS certificates and configurations.

**Subcommands:**
- `get <key-id>` - Get TLS certificate and key

```bash
xkmsctl tls get my-tls-cert
```

[Documentation](./tls.md)

---

### bootstrap - Secure CA bundle bootstrap

Manage secure CA bundle retrieval, DANE/TLSA records, Noise protocol keys, and SPKI pins for bootstrapping new nodes into the PKI.

**Subcommands:**
- `auto` - Auto-bootstrap using all configured methods (DANE, Noise, SPKI, Direct)
- `dane generate-tlsa` - Generate TLSA records from a CA certificate
- `dane verify-tlsa` - Verify a certificate against TLSA DNS records
- `dane show-tlsa` - Display TLSA records from DNS
- `noise generate-key` - Generate a new Curve25519 static keypair
- `noise show-key` - Derive public key from a static private key
- `noise show-spki-pin` - Compute SPKI SHA-256 pin from a TLS certificate
- `spki show-pin` - Compute SPKI SHA-256 pin from a certificate

```bash
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise-static.key
xkmsctl bootstrap noise show-key --key-file /etc/xkms/noise-static.key
xkmsctl bootstrap noise show-spki-pin --server kms.example.com:8443
xkmsctl bootstrap auto --output-file /etc/xkms/ca-bundle.pem
```

[Documentation](./bootstrap.md)

---

### custodian - Custodian group management

Manage custodian groups for Shamir secret sharing ceremonies. Custodian groups define trusted individuals who hold barrier shares.

**Subcommands:**
- `create` - Create a new custodian group with threshold/total shares
- `list` - List all custodian groups
- `show` - Show details for a custodian group
- `delete` - Delete a custodian group
- `add-member` - Add a member to a custodian group
- `remove-member` - Remove a member from a custodian group
- `distribute` - Distribute Shamir shares to group members

```bash
xkmsctl custodian create --name "Ops Team" --threshold 3 --total 5
xkmsctl custodian add-member --group-id my-group --user-id user-123
xkmsctl custodian distribute --group-id my-group
xkmsctl custodian list
```

---

### tenant - Multi-tenant management

Manage tenants and their per-tenant cryptographic barriers. Each tenant gets an isolated namespace with its own barrier, keys, and certificates.

**Subcommands:**
- `create` - Create a new tenant
- `list` - List all tenants
- `show` - Show details for a tenant
- `delete` - Delete a tenant and all associated resources
- `barrier-init` - Initialize a per-tenant barrier
- `barrier-unseal` - Unseal a per-tenant barrier with a Shamir share
- `barrier-status` - Show per-tenant barrier status

```bash
xkmsctl tenant create --id acme --name "Acme Corporation"
xkmsctl tenant barrier-init --id acme --threshold 3 --shares 5
xkmsctl tenant barrier-unseal --id acme --share <base64-share>
xkmsctl tenant barrier-status --id acme
```

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
xkmsctl fido2 list-devices
xkmsctl fido2 register alice
xkmsctl fido2 authenticate --username alice
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
xkmsctl admin create bob --password secretpass
xkmsctl admin list
xkmsctl admin disable bob
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
xkmsctl user register alice
xkmsctl user login --username alice
xkmsctl user list
xkmsctl user credentials alice
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
xkmsctl migrate plan --from software --to pkcs11

# Execute migration with filters
xkmsctl migrate execute \
  --from software \
  --to pkcs11 \
  --key-types signing \
  --parallel 4

# Validate migrated key
xkmsctl migrate validate \
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
xkmsctl frost keygen \
  --key-id mykey \
  --threshold 2 \
  --total 3 \
  --export-dir ./packages

# Participant imports their package
xkmsctl frost import --package ./packages/participant_1.json

# Round 1: Generate commitments
xkmsctl frost round1 --key-id mykey --output commitment.json

# Round 2: Generate signature share
xkmsctl frost round2 \
  --key-id mykey \
  --message "sign this" \
  --nonces commitment.json.nonces \
  --commitments p1.json,p2.json,p3.json \
  --output share.json

# Aggregate signatures
xkmsctl frost aggregate \
  --key-id mykey \
  --message "sign this" \
  --commitments p1.json,p2.json \
  --shares share1.json,share2.json \
  --output signature.bin
```

[Documentation](./frost.md)

---

### barrier - Barrier encryption management

Manage the encrypted storage barrier that protects all key material at rest.

**Subcommands:**
- `init` - Initialize a new barrier with a sealed root key
- `unseal` - Unseal the barrier to enable storage operations
- `seal` - Seal the barrier, zeroing the encryption key in memory
- `status` - Display the current barrier state

```bash
xkmsctl barrier init --strategy software
xkmsctl barrier unseal
xkmsctl barrier status
xkmsctl barrier seal
```

[Documentation](./barrier.md)

---

### pin - PIN management

Manage the dual-PIN authentication system (SO PIN + User PIN) for barrier access control.

**Subcommands:**
- `set-so` - Set the Security Officer PIN
- `set-user` - Set the User PIN (requires SO PIN)
- `change-so` - Change the SO PIN
- `change-user` - Change the User PIN
- `verify` - Verify a PIN
- `status` - Display PIN and lockout status
- `reset-lockout` - Reset the lockout counter (requires SO PIN)

```bash
xkmsctl pin set-so
xkmsctl pin set-user
xkmsctl pin verify --type user
xkmsctl pin status
xkmsctl pin reset-lockout
```

[Documentation](./pin.md)

---

### piv - PIV smart card operations

Manage PIV (Personal Identity Verification) certificates and keys across backends.

**Subcommands:**
- `list` - List PIV slots and their status
- `get <slot>` - Get certificate from a PIV slot
- `store <slot>` - Store a certificate in a PIV slot
- `delete <slot>` - Delete certificate from a PIV slot
- `generate <slot>` - Generate a key pair in a PIV slot
- `import <slot>` - Import a certificate into a PIV slot
- `export <slot>` - Export certificate from a PIV slot
- `csr <slot>` - Generate a CSR for a PIV slot key

```bash
xkmsctl piv list --backend pkcs11
xkmsctl piv generate 9a --algorithm ecdsap256 --subject "CN=Auth"
xkmsctl piv csr 9a --subject "CN=Auth,O=MyOrg"
xkmsctl piv export 9a --format pem
```

[Documentation](./piv.md)

---

---

## xkey CLI Commands

The `xkey` application provides client-side commands for interacting with xkms servers from the desktop.

### auth - Server authentication

Manage authentication with xkms servers via WebAuthn. Server entries and JWT tokens are stored locally.

**Subcommands:**
- `register` - Register with a new xkms server (SPKI pin or setup token)
- `login` - Authenticate to a registered server via WebAuthn
- `status` - Show authentication status for all servers
- `token` - Print current JWT token for a server (pipe-friendly)

```bash
xkey auth register --server https://xkms.example.com:8443 --spki-pin abc123
xkey auth login --server https://xkms.example.com:8443
xkey auth status
export XKMS_TOKEN=$(xkey auth token --server https://xkms.example.com:8443)
```

[Documentation](./auth.md)

---

### share - Key share management

Manage locally stored Shamir secret shares for barrier unseal operations.

**Subcommands:**
- `list` - List locally stored shares
- `receive` - Poll server for distributed shares
- `import` - Import a share from a JSON file
- `export` - Export a share to a JSON file
- `unseal` - Submit a share to unseal the server barrier
- `delete` - Delete a locally stored share

```bash
xkey share list
xkey share receive --server grpc://xkmsd.example.com:9090
xkey share import --file /tmp/share-1.json
xkey share unseal --server grpc://xkmsd.example.com:9090 --group-id barrier-ops
```

[Documentation](./share.md)

---

### cert - Client certificate management

Manage client certificates for mTLS authentication with xkms servers. Uses PIV slot keys for CSR generation.

**Subcommands:**
- `request` - Request a certificate from a server CA
- `show` - Show current certificate details in a PIV slot
- `export` - Export certificate to a PEM file

```bash
xkey cert request --server https://xkms.example.com:8443 --cn "user@example.com" --spki-pin abc123
xkey cert show
xkey cert export --file /tmp/client-cert.pem
```

---

### extension - Browser extension management

Manage the browser extension native messaging host and headless autofill IPC server.

**Subcommands:**
- `install [chrome|firefox|all]` - Install native messaging manifest
- `uninstall [chrome|firefox|all]` - Remove native messaging manifest
- `status` - Show native messaging manifest status
- `serve` - Run headless autofill IPC server
- `host` - Run native messaging host (invoked by browser)

```bash
xkey extension install
xkey extension status
xkey extension serve --barrier-password "secret"
xkey extension serve --no-barrier --log-level debug
```

[Documentation](./extension.md)

---

## Common Workflows

### Local Key Generation and Signing

```bash
# Generate a signing key locally
xkmsctl --local key generate my-key \
  --key-type signing \
  --algorithm ed25519

# Sign data
xkmsctl --local key sign my-key "message to sign" \
  --output signature.bin

# Verify signature
xkmsctl --local key verify my-key \
  "message to sign" \
  signature.bin
```

### Remote Server Access with TLS

```bash
# Login to get JWT token
xkmsctl --server https://xkms.example.com \
  --tls-ca ca.pem \
  user login --username alice

# Use token for subsequent commands
xkmsctl --server https://xkms.example.com \
  --tls-ca ca.pem \
  --token <jwt-token> \
  key list
```

### HSM Key Operations

```bash
# Generate key in PKCS#11 HSM
xkmsctl --backend pkcs11 key generate hsm-key \
  --key-type signing \
  --algorithm rsa \
  --key-size 4096

# Sign with HSM key
xkmsctl --backend pkcs11 key sign hsm-key document.pdf
```

### Multi-Backend Migration

```bash
# Migrate all signing keys from software to TPM
xkmsctl migrate execute \
  --from software \
  --to tpm2 \
  --key-types signing \
  --delete-source \
  --parallel 8 \
  --force
```

## Configuration File

The CLI supports YAML configuration files to avoid repetitive flags:

**Location:** `$HOME/.xkms.yaml` (default) or specify with `--config`

```yaml
# Backend configuration
backend: software
key_dir: /var/lib/xkms/keys

# Server connection
server: unix:///var/run/xkms.sock
# server: https://xkms.example.com:8443

# TLS configuration
tls:
  ca_cert: /etc/xkms/ca.pem
  client_cert: /etc/xkms/client.pem
  client_key: /etc/xkms/client-key.pem
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
$ xkmsctl key list
KEY ID              ALGORITHM    TYPE        CREATED
my-key              Ed25519      signing     2025-01-15T10:30:00Z
encryption-key      AES-256-GCM  encryption  2025-01-15T11:00:00Z
```

### JSON Format

Machine-parsable structured output:
```bash
$ xkmsctl key list -o json
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
$ xkmsctl key list -o table
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
xkmsctl -v key generate test-key
[VERBOSE] Creating backend: software
[VERBOSE] Generating key: test-key
[VERBOSE] Key type: signing
[VERBOSE] Algorithm: Ed25519
Successfully generated key: test-key
```

## Environment Variables

The following environment variables can be used instead of flags:

- `XKMS_CONFIG` - Configuration file path
- `XKMS_BACKEND` - Default backend
- `XKMS_SERVER` - Server URL
- `XKMS_TOKEN` - JWT authentication token

Example:
```bash
export XKMS_BACKEND=pkcs11
export XKMS_SERVER=https://xkms.example.com
xkmsctl key list
```

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
xkmsctl completion bash > /etc/bash_completion.d/xkmsctl

# Zsh
xkmsctl completion zsh > ~/.zsh/completion/_xkmsctl

# Fish
xkmsctl completion fish > ~/.config/fish/completions/xkmsctl.fish

# PowerShell
xkmsctl completion powershell > xkmsctl.ps1
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
- GitHub: https://github.com/jeremyhahn/go-xkms
- Documentation: https://github.com/jeremyhahn/go-xkms/tree/main/docs

## License

go-xkms is dual-licensed under AGPL-3.0 and commercial license.
See LICENSE file for details or contact licensing@automatethethings.com for commercial licensing.
