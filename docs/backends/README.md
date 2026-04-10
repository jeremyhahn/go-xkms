# Backend Documentation

This directory contains documentation for all supported storage backends in go-xkms.

## Available Backends

### Software

- **[Software](software.md)** - Full-featured software backend (asymmetric + symmetric encryption)

### Hardware Security Modules

- **[TPM 2.0](tpm2.md)** - Trusted Platform Module 2.0
- **[PKCS#11](pkcs11.md)** - Generic Hardware Security Module support (also supports YubiKey PIV via `libykcs11`)
- **[Nitrokey HSM](nitrokey-hsm.md)** - Nitrokey HSM device (via PKCS#11 backend)
- **[Phone](phone/)** - Android phone as HSM via BLE/USB (TEE/StrongBox)

### Cloud Key Management Services

- **[AWS KMS](awskms.md)** - Amazon Web Services Key Management Service
- **[GCP KMS](gcpkms.md)** - Google Cloud Platform Key Management Service
- **[Azure Key Vault](azurekv.md)** - Microsoft Azure Key Vault
- **[HashiCorp Vault](vault.md)** - HashiCorp Vault Transit Engine

## Backend Selection Guide

Each backend implements the `types.KeyProvider` interface, providing a consistent API for key operations. The `xkms.Backend` wrapper adds certificate storage, TLS helpers, and unified key ID support on top of any KeyProvider.

| Backend | Asymmetric | Symmetric | Hardware | Cloud | Sealing | Attestation |
|---------|-----------|-----------|----------|-------|---------|-------------|
| Software | ✓ | ✓ | ✗ | ✗ | ✓ | ✗ |
| TPM 2.0 | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| PKCS#11 | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| AWS KMS | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| GCP KMS | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| Azure KV | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| Vault | ✓ | ✓ | Optional | Optional | ✗ | ✗ |
| Phone | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |

## See Also

- [Backend Architecture](../architecture/backend-registry.md)
- [Quick Start](../usage/quickstart.md)
- [Getting Started](../usage/getting-started.md)
- [Configuration Guide](../configuration/)
