# Usage Documentation

This directory contains guides and tutorials for using go-keychain in your applications.

## Getting Started

- [Getting Started](getting-started.md) - Quick start guide to using go-keychain
- [API Parity](api-parity.md) - API compatibility across different backends

## Key Management

- [Key Import/Export](key-import-export.md) - Importing and exporting cryptographic keys
- [Certificate Management](certificate-management.md) - Managing X.509 certificates

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
