# Backend Documentation

This directory contains documentation for all supported storage backends in go-xkms.

## Available Backends

### Software

- **[Software](software.md)** - Full-featured software backend (asymmetric + symmetric encryption)

### Hardware Security Modules

- **[TPM 2.0](tpm2.md)** - Trusted Platform Module 2.0
- **[PKCS#11](pkcs11.md)** - Generic Hardware Security Module support (also supports YubiKey PIV via `libykcs11`). This is xkms *consuming* an HSM; reference docs in [../pkcs11/backend/](../pkcs11/backend/README.md). Not to be confused with the PKCS#11 module xkms *provides* ([../pkcs11/module/](../pkcs11/module/README.md)).
- **[Nitrokey HSM](nitrokey-hsm.md)** - Nitrokey HSM device (via PKCS#11 backend)
- **Phone** - Android phone as HSM via BLE/USB (TEE/StrongBox). Implemented at `pkg/backend/phone/`; no backend guide written yet.

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
| PKCS#11 | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| AWS KMS | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| GCP KMS | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Azure KV | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Vault | ✓ | ✓ | Optional | Optional | ✓ | ✗ |
| Phone | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |

Every backend except Phone implements `types.Sealer` — a `sealer.go` in the
backend package (`CanSeal`/`Seal`/`Unseal`), with the Software backend's in
`software.go`. What differs is where the sealing key lives: TPM 2.0 and PKCS#11
seal against hardware-resident keys, the cloud backends against a
provider-managed symmetric key. `CanSeal()` reports false until the backend is
initialized, so check it rather than assuming from this table.

## See Also

- [Backend Architecture](../architecture/overview.md) - the registry itself is `pkg/xkms/registry.go`
- [Quick Start](../../xkey/docs/usage/quickstart.md)
- [Getting Started](../../xkey/docs/usage/getting-started.md)
- [Configuration Guide](../configuration/)
