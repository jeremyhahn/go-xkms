# Configuration Documentation

This directory contains configuration guides for various aspects of go-keychain.

## Configuration Topics

### Build Configuration
- [Build System](build-system.md) - Build tags, compilation options, and cross-platform builds

### Encryption Configuration
- [AEAD Auto-Selection](aead-auto-selection.md) - Automatic AEAD algorithm selection based on key types
- [AEAD Bytes Tracking](aead-bytes-tracking.md) - Encrypted data format and byte layout
- [Symmetric Encryption](symmetric-encryption.md) - Symmetric encryption configuration and usage

### Backend-Specific Configuration
- [TPM2 Session Encryption](tpm2-session-encryption.md) - TPM 2.0 session encryption configuration

## Configuration Best Practices

1. **Security**: Always use hardware-backed storage for production environments
2. **Key Types**: Choose appropriate key types and algorithms for your use case
3. **Storage**: Configure appropriate storage backends for your deployment model
4. **Encryption**: Enable session encryption for TPM2 backends in production

## See Also

- [Architecture Overview](../architecture/overview.md)
- [Backend Documentation](../backends/)
- [Getting Started Guide](../usage/getting-started.md)
