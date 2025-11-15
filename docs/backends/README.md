# Backend Documentation

This directory contains documentation for all supported storage backends in go-keychain.

## Available Backends

### Hardware Security Modules

- **[PKCS#11](pkcs11.md)** - Generic Hardware Security Module support
- **[SmartCard-HSM](smartcardhsm.md)** - CardContact SmartCard-HSM with DKEK support
- **[Nitrokey HSM](nitrokey-hsm.md)** - Nitrokey HSM device (uses SmartCard-HSM)
- **[TPM2](tpm2.md)** - Trusted Platform Module 2.0
- **[YubiKey](yubikey.md)** - YubiKey PIV smart card

### Cloud Key Management Services

- **[AWS KMS](awskms.md)** - Amazon Web Services Key Management Service
- **[GCP KMS](gcpkms.md)** - Google Cloud Platform Key Management Service
- **[Azure Key Vault](azurekv.md)** - Microsoft Azure Key Vault
- **[HashiCorp Vault](vault.md)** - HashiCorp Vault Transit Engine

### Software Backends

- **[PKCS#8](pkcs8.md)** - File-based PKCS#8 key storage
- **[AES](../architecture/symmetric-encryption.md)** - File-based AES symmetric key storage

## Backend Selection Guide

Each backend provides different features and security characteristics:

| Backend | Asymmetric Keys | Symmetric Keys | Hardware-backed | Cloud-based | Requires HSM | DKEK Backup |
|---------|----------------|----------------|-----------------|-------------|--------------|-------------|
| PKCS#8  | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| AES     | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| PKCS#11 | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| SmartCard-HSM | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| TPM2    | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| YubiKey | ✓ | ✗ | ✓ | ✗ | ✓ | ✗ |
| AWS KMS | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| GCP KMS | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| Azure KV | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| Vault   | ✓ | ✓ | Optional | Optional | ✗ | ✗ |

## See Also

- [Backend Architecture](../architecture/backend-registry.md)
- [Getting Started](../usage/getting-started.md)
- [Configuration Guide](../configuration/)
