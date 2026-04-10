# go-xkms Documentation

Comprehensive documentation for the go-xkms cryptographic key management library.

## Overview

go-xkms is a unified cryptographic key management library for Go that provides a consistent interface across multiple storage backends, from software-based file storage to hardware security modules and cloud key management services.

## Documentation Structure

### [Architecture](architecture/)
Core architectural concepts, design patterns, and technical specifications:
- [Overview](architecture/overview.md) - System architecture and design philosophy
- [API Specifications](architecture/api-specifications.md) - API design and interface contracts
- [Server Architecture](architecture/server-architecture.md) - Server design and backend registry
- [Storage](architecture/storage.md) - Storage interfaces and abstraction layer
- [Symmetric Encryption](architecture/symmetric-encryption.md) - Symmetric key support architecture
- [Hardware Certificate Storage](architecture/hardware-certificate-storage.md) - HSM certificate storage design
- [RBAC](architecture/rbac.md) - Role-based access control

### [Backends](backends/)
Backend-specific documentation for all supported storage systems:
- **Software**: [Software](backends/software.md) (asymmetric + symmetric, default backend), [PKCS#8](backends/pkcs8.md)
- **Hardware**: [TPM 2.0](backends/tpm2.md), [PKCS#11](backends/pkcs11.md), [Nitrokey HSM](backends/nitrokey-hsm.md)
- **Cloud**: [AWS KMS](backends/awskms.md), [GCP KMS](backends/gcpkms.md), [Azure Key Vault](backends/azurekv.md), [HashiCorp Vault](backends/vault.md)
- **Quantum**: [Post-Quantum Cryptography](backends/quantum.md)

### [Configuration](configuration/)
Configuration guides for various components:
- [Build System](configuration/build-system.md) - Build tags and compilation options
- [AEAD Configuration](configuration/aead-auto-selection.md) - Authenticated encryption setup
- [Symmetric Encryption](configuration/symmetric-encryption.md) - Symmetric key configuration
- [TPM2 Session Encryption](configuration/tpm2-session-encryption.md) - TPM session security

### [Bootstrap](bootstrap/)
Secure trust establishment and server initialization:
- [Overview](bootstrap/README.md) - Bootstrap architecture, DANE/Noise/SPKI trust methods, custodian setup

### [Usage](../xkey/docs/usage/)
CLI usage guides and tutorials have moved to [xkey/docs/usage/](../xkey/docs/usage/README.md).

### [xKey Application](../xkey/docs/)
xKey is the desktop GUI and CLI application built on go-xkms. All xKey documentation (setup wizard, auto-unseal, FIDO2 daemon, enterprise mode, password management, etc.) lives in [xkey/docs/](../xkey/docs/README.md).

### [Testing](testing/)
Testing documentation and best practices:
- [Integration Tests](testing/integration-tests.md) - End-to-end testing guide
- [Docker Testing](testing/docker-testing.md) - Isolated test environments

### [Deployment](deployment/)
Deployment guides and production configurations:
- [Docker Deployment](deployment/docker.md) - Complete Docker deployment guide
- [Docker Quick Start](deployment/docker-quickstart.md) - 5-minute Docker setup

### [Sealed Storage](sealed-storage/)
Encrypted-at-rest storage and credential management:
- [Sealed Backend](sealed-storage/README.md) - Transparent value encryption via types.Sealer
- [PlatformStore](platform-store/README.md) - Named-secret credential store (macOS Keychain analog)
- [Static Passwords](staticpw/README.md) - Password manager with multi-tenant support and encryption

### [FIPS 140](fips/)
FIPS compliance and algorithm selection:
- [FIPS Strategy](fips/README.md) - GOFIPS140 detection, KDF selection, and PasswordHasher

### [Development](development/)
Development and contributor documentation:
- [Encoding Interop Status](development/encoding-interop-status.md) - JWK/JWT/JWE test implementation status

## Quick Start

The simplest way to get started is with `AutoInitialize`, which discovers all compiled-in backends and sets them up automatically:

```go
import (
    "crypto/elliptic"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // See what backends are compiled in
    fmt.Println("Available backends:", xkms.SupportedBackends())

    // Auto-initialize all compiled-in backends with defaults
    if err := xkms.AutoInitialize(nil); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Generate a key using the service API
    key, err := xkms.GenerateKey(&types.KeyAttributes{
        CN:           "my-signing-key",
        StoreType:    types.BackendType("software"),
        KeyAlgorithm: x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Sign data
    sig, err := xkms.Sign("software:::my-signing-key", []byte("hello"), nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", sig)
}
```

For client/server deployments, use the Go SDK:

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

client, _ := xkms.NewFromURL("https://localhost:8443")
defer client.Close()
client.Connect(ctx)

resp, _ := client.GenerateKey(ctx, &xkms.GenerateKeyRequest{
    KeyID:   "my-key",
    Backend: "software",
    KeyType: "EC",
    Curve:   "P-256",
})
```

See the [Getting Started](usage/getting-started.md) guide for all initialization patterns.

## Key Features

- **Unified Interface**: Single API across all backends
- **Auto-Discovery**: Registry auto-discovers compiled-in backends at startup
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
