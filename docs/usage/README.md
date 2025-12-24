# Usage Documentation

This directory contains guides and tutorials for using go-keychain in your applications.

## Getting Started

- [Getting Started](getting-started.md) - Quick start guide to using go-keychain
- [API Parity](api-parity.md) - API compatibility across different backends

## Command Line Interface

The go-keychain CLI provides a comprehensive command-line interface for managing keys, certificates, users, and cryptographic operations.

- [CLI Documentation](cli/README.md) - Complete CLI reference and usage guide

Key CLI topics:
- [Key Management Commands](cli/key.md) - Generate, import, export, and manage cryptographic keys
- [Certificate Management](cli/cert.md) - Issue, import, and manage X.509 certificates
- [Backend Management](cli/backends.md) - Configure and switch between storage backends
- [User Management](cli/user.md) - User account operations and permissions
- [Administrator Management](cli/admin.md) - Administrative operations and controls
- [FIDO2 Security Keys](cli/fido2.md) - Hardware security key operations
- [Key Migration](cli/migrate.md) - Migrate keys between backends
- [Threshold Signatures (FROST)](cli/frost.md) - Distributed threshold cryptography
- [TLS Operations](cli/tls.md) - TLS certificate and key operations
- [DKEK Operations](cli/dkek.md) - Domain Key Encryption Key management

## Key Management

- [Key Import/Export](key-import-export.md) - Importing and exporting cryptographic keys
- [Certificate Management](certificate-management.md) - Managing X.509 certificates

## Authentication & Authorization

- [User Management](user.md) - User accounts, roles, and permissions
- [WebAuthn](webauthn.md) - Passwordless authentication with FIDO2/passkeys

## Usage Guides

### Basic Operations

1. **Initialize a keychain** with your chosen backend
2. **Generate or import keys** using the appropriate key type
3. **Perform cryptographic operations** (sign, verify, encrypt, decrypt)
4. **Manage certificates** for TLS and code signing

### Common Use Cases

- **TLS Server Authentication**: Generate TLS certificates and keys
- **Code Signing**: Sign and verify code artifacts
- **Data Encryption**: Encrypt sensitive data at rest
- **Hardware Security**: Use HSM or TPM for key protection

## Examples

See the `examples/` directory in the repository for complete working examples:

- `examples/basic/` - Basic key generation and usage
- `examples/certificates/` - Certificate management
- `examples/signing/` - Digital signatures
- `examples/symmetric-encryption/` - Symmetric encryption
- `examples/tls/` - TLS client and server

## See Also

- [Backend Documentation](../backends/)
- [Configuration Guide](../configuration/)
- [Testing Documentation](../testing/)
