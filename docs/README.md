# go-keychain Documentation

Comprehensive documentation for the go-keychain cryptographic key management library.

## Overview

go-keychain is a unified cryptographic key management library for Go that provides a consistent interface across multiple storage backends, from software-based file storage to hardware security modules and cloud key management services.

## Documentation Structure

### [Architecture](architecture/)
Core architectural concepts, design patterns, and technical specifications:
- [Overview](architecture/overview.md) - System architecture and design philosophy
- [API Specifications](architecture/api-specifications.md) - API design and interface contracts
- [Backend Registry](architecture/backend-registry.md) - Backend registration and discovery
- [Storage Abstraction](architecture/storage-abstraction.md) - Unified storage interface
- [Symmetric Encryption](architecture/symmetric-encryption.md) - Symmetric key support architecture
- [Hardware Certificate Storage](architecture/hardware-certificate-storage.md) - HSM certificate storage design

### [Backends](backends/)
Backend-specific documentation for all supported storage systems:
- **Software**: [PKCS#8](backends/pkcs8.md), [AES](backends/)
- **Hardware**: [PKCS#11](backends/pkcs11.md), [SmartCard-HSM](backends/smartcardhsm.md), [TPM 2.0](backends/tpm2.md), [YubiKey](backends/yubikey.md)
- **Cloud**: [AWS KMS](backends/awskms.md), [GCP KMS](backends/gcpkms.md), [Azure Key Vault](backends/azurekv.md), [HashiCorp Vault](backends/vault.md)

### [Configuration](configuration/)
Configuration guides for various components:
- [Build System](configuration/build-system.md) - Build tags and compilation options
- [AEAD Configuration](configuration/aead-auto-selection.md) - Authenticated encryption setup
- [Symmetric Encryption](configuration/symmetric-encryption.md) - Symmetric key configuration
- [TPM2 Session Encryption](configuration/tpm2-session-encryption.md) - TPM session security

### [Usage](usage/)
User guides and tutorials:
- [Getting Started](usage/getting-started.md) - Quick start guide
- [Key Import/Export](usage/key-import-export.md) - Key management operations
- [Certificate Management](usage/certificate-management.md) - X.509 certificate handling
- [API Parity](usage/api-parity.md) - Cross-backend compatibility

### [Testing](testing/)
Testing documentation and best practices:
- [Integration Tests](testing/integration-tests.md) - End-to-end testing guide
- [Docker Testing](testing/docker-testing.md) - Isolated test environments

### [Deployment](deployment/)
Deployment guides and production configurations:
- [Docker Deployment](deployment/docker.md) - Complete Docker deployment guide
- [Docker Quick Start](deployment/docker-quickstart.md) - 5-minute Docker setup

### [Development](development/)
Development and contributor documentation:
- [Encoding Interop Status](development/encoding-interop-status.md) - JWK/JWT/JWE test implementation status

## Quick Start

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/backend/software"
)

// Create a software backend
backend := software.NewSoftwareBackend(config)

// Create keychain
kc := keychain.New(backend)

// Generate a key
keyID, err := kc.GenerateKey(keychain.KeyTypeRSA, 2048)
```

## Key Features

- **Unified Interface**: Single API across all backends
- **Multiple Backends**: Support for file, HSM, TPM, and cloud storage
- **Key Types**: RSA, ECDSA, Ed25519, AES
- **Standards Compliant**: PKCS#8, PKCS#11, TPM 2.0, JWK, JWT
- **Certificate Management**: X.509 certificate lifecycle management
- **High Performance**: Lock-free algorithms, optimized for low latency
- **Type Safe**: No pointer magic or unsafe operations
- **Well Tested**: 90%+ code coverage with meaningful tests

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic/` - Basic key operations
- `examples/certificates/` - Certificate management
- `examples/signing/` - Digital signatures
- `examples/symmetric-encryption/` - Symmetric encryption
- `examples/tls/` - TLS client and server
- `examples/advanced/` - Advanced patterns

## Building

```bash
# Build with all backends
make build

# Build with specific backends
go build -tags="pkcs11 tpm2" ./...

# Run tests
make test

# Run integration tests
make integration-test
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## License

Copyright (c) 2025 Jeremy Hahn. Licensed under the AGPL-3.0 License.
