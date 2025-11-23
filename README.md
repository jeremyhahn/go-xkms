[logo]: https://github.com/jeremyhahn/go-keychain/raw/main/logo.png "go-keychain"

# go-keychain

[![Go Version](https://img.shields.io/badge/Go-1.25.1-blue.svg)](https://golang.org)
[![Version](https://img.shields.io/badge/version-v0.1.6--alpha-green.svg)](https://github.com/jeremyhahn/go-keychain/releases)
[![Tests](https://img.shields.io/badge/tests-151%20passing-brightgreen.svg)](test/integration)
[![Coverage](https://img.shields.io/badge/coverage-92.5%25-brightgreen.svg)](pkg)
[![Backends](https://img.shields.io/badge/backends-10-blue.svg)](#backend-support-)
[![AGPL-3.0 License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE-AGPL-3.txt)
[![Commercial License](https://img.shields.io/badge/license-Commercial-green.svg)](LICENSE-COMMERCIAL.md)

A secure cryptographic key and certificate management solution for on-prem, hybrid, and/or cloud.

## Features at a Glance

- **10 Production-Ready Backends**: PKCS#8, AES, PKCS#11, SmartCard-HSM, TPM2, YubiKey, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault
- **Complete Key Management**: Generate, store, retrieve, rotate, and delete keys (RSA, ECDSA, Ed25519, AES)
- **Symmetric Encryption**: AES-GCM (128/192/256-bit) with AEAD safety support across all backends
- **Certificate Operations**: Full X.509 certificate lifecycle including chains and CRL support
- **Crypto Operations**: Sign, verify, encrypt, decrypt with standard Go interfaces
- **Thread-Safe**: Safe for concurrent operations with proper synchronization
- **Well-Tested**: 92.5% unit test coverage with 151 passing integration tests
- **Pluggable Architecture**: Easy to add custom backends and storage implementations
- **Unified Facade**: Simple API that abstracts backend complexity

## Overview

**go-keychain** provides a unified interface for managing cryptographic keys and certificates across multiple backend types, from simple file-based storage to hardware security modules and cloud KMS services.

### Core Focus

- **Keys**: Generate, store, retrieve, rotate cryptographic keys
- **Certificates**: Manage X.509 certificates, chains, and CRLs
- **Backends**: Pluggable storage (PKCS#8, PKCS#11, TPM2, Cloud KMS)
- **Standards**: PKCS#8, PEM, X.509, CRL formats

### Design Principles

- **Clean Architecture**: Clear separation of concerns, interface-based design
- **Pluggable Backends**: Easy to add new storage types
- **Unified Facade**: Single API for all backends - no leaky abstractions
- **Thread-Safe**: Safe for concurrent operations
- **Well-Tested**: 92.5% unit test coverage, 151 passing integration tests
- **Production-Ready**: v0.1.6-alpha with 10 fully working backends
- **Focused Scope**: Just keys and certificates - no server/events/secrets

---

## Features

### Key Management

- **Asymmetric Keys**: RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Symmetric Keys**: AES-GCM (128/192/256-bit) with authenticated encryption
- **Storage**: Secure storage with optional password encryption
- **Operations**: Sign, verify, encrypt, decrypt (both asymmetric and symmetric)
- **Rotation**: Safe key rotation with old key deletion
- **Multiple Backends**: PKCS#8, AES, PKCS#11 (HSM), TPM2, AWS/GCP/Azure KMS, Vault

### Certificate Management

- **CRUD Operations**: Store, retrieve, delete certificates
- **Certificate Chains**: Build and validate certificate chains
- **CRL Support**: Certificate Revocation List management
- **Validation**: Certificate verification with configurable options
- **Revocation Checking**: Check if certificates are revoked
- **Hardware Storage**: Native PKCS#11 HSM and TPM2 NV RAM certificate storage
- **Hybrid Mode**: Automatic failover between hardware and external storage

### Cryptographic Operations

- **Signing**: All asymmetric key types with multiple hash algorithms
- **Verification**: Multi-algorithm signature verification
- **Asymmetric Encryption**: RSA encryption with PKCS1v15, PSS and OAEP padding
- **Symmetric Encryption**: AES-GCM authenticated encryption with additional data (AEAD)
- **TLS Integration**: Easy TLS certificate configuration
- **Standard Interfaces**: Implements `crypto.Signer` and `crypto.Decrypter`

### Backend Support

| Backend | Description | Use Case | Status |
|---------|-------------|----------|--------|
| **PKCS#8** | File-based asymmetric keys | Development, testing, simple deployments | Complete |
| **AES** | File-based symmetric keys | Local symmetric encryption | Complete |
| **PKCS#11** | Hardware Security Module | High-security environments, compliance | Complete |
| **SmartCard-HSM** | CardContact SmartCard-HSM with DKEK | Hardware-backed keys with distributed key backup | Complete |
| **TPM2** | Trusted Platform Module | Device attestation, secure boot | Complete |
| **YubiKey** | YubiKey PIV (Smart Card) | Hardware-backed keys, 2FA, portable HSM | Complete |
| **AWS KMS** | Amazon Key Management Service | AWS cloud deployments | Complete |
| **GCP KMS** | Google Cloud KMS | GCP cloud deployments | Complete |
| **Azure Key Vault** | Azure Key Vault | Azure cloud deployments | Complete |
| **HashiCorp Vault** | HashiCorp Vault Transit Engine | Multi-cloud, on-premise | Complete |

---

## Client Interfaces

go-keychain provides **5 client interfaces** for accessing key and certificate operations:

| Interface | Protocol | Coverage | Status | Use Case |
|-----------|----------|----------|--------|----------|
| **REST** | HTTP/HTTPS | 100% (17/17) | Complete | Web services, language-agnostic |
| **gRPC** | gRPC/Protobuf | 100% (17/17) | Complete | High-performance RPC |
| **QUIC** | HTTP/3 over QUIC | 100% (17/17) | Complete | Low-latency, UDP-based |
| **CLI** | Command-line | 100% (17/17) | Complete | Interactive, scripts |
| **MCP** | JSON-RPC | 100% (17/17) | Complete | Model Context Protocol |

All interfaces expose the complete KeyStore API for keys and certificates. See [docs/api-parity.md](docs/api-parity.md) for detailed method coverage.

### Interface Examples

**REST API:**
```bash
curl -X POST http://localhost:8443/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_id": "my-key", "key_type": "rsa", "key_size": 2048}'
```

**gRPC:**
```go
conn, _ := grpc.Dial("localhost:9443", grpc.WithInsecure())
client := pb.NewKeychainServiceClient(conn)
resp, _ := client.GenerateKey(ctx, &pb.GenerateKeyRequest{...})
```

**CLI:**
```bash
keychain key generate --name my-key --type rsa --size 2048
keychain key list
keychain cert get my-key
```

**MCP (JSON-RPC):**
```json
{"jsonrpc": "2.0", "method": "keychain.generateKey",
 "params": {"key_id": "my-key", "key_type": "rsa"}, "id": 1}
```

**QUIC (HTTP/3):**
```bash
curl --http3 https://localhost:8444/api/v1/keys
```

---

## Installation

```bash
go get github.com/jeremyhahn/go-keychain
```

---

## Quick Start

### Simple Usage with Facade (Recommended)

```go
package main

import (
    "crypto"
    "log"

    "github.com/jeremyhahn/go-keychain/internal/server"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
    // Initialize the keychain with auto-detected backends
    // This sets up PKCS8, Software, and AES backends automatically
    err := server.Initialize(nil)
    if err != nil {
        log.Fatal(err)
    }
    defer keychain.Close()

    // Generate RSA key using the default backend
    key, err := keychain.KeyByID("my-signing-key")
    if err != nil {
        // Key doesn't exist, generate it
        ks, _ := keychain.DefaultBackend()

        attrs := &types.KeyAttributes{
            CN:        "my-signing-key",
            KeyType:   types.KeyTypeTLS,
            StoreType: types.StorePKCS8,
            RSAAttributes: &types.RSAAttributes{
                KeySize: 2048,
            },
        }

        key, err = ks.GenerateRSA(attrs)
        if err != nil {
            log.Fatal(err)
        }
    }

    // Use the key for signing
    signer, err := keychain.Signer("my-signing-key")
    if err != nil {
        log.Fatal(err)
    }

    signature, err := signer.Sign(nil, []byte("data to sign"), crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Generated key and created signature: %x", signature[:16])
}
```

### Advanced: Using Specific Backends

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
    // Create file-based storage
    keyStorage, _ := file.New("./keys")
    certStorage, _ := file.New("./certs")

    // Create PKCS#8 backend
    pkcs8Backend, _ := pkcs8.NewBackend(&pkcs8.Config{
        KeyStorage: keyStorage,
    })
    defer pkcs8Backend.Close()

    // Create keystore
    ks, _ := keychain.New(&keychain.Config{
        Backend:     pkcs8Backend,
        CertStorage: certStorage,
    })
    defer ks.Close()

    // Generate RSA key
    attrs := &types.KeyAttributes{
        CN:        "example-key",
        KeyType:   types.KeyTypeTLS,
        StoreType: types.StorePKCS8,
        RSAAttributes: &types.RSAAttributes{
            KeySize: 2048,
        },
    }

    key, err := ks.GenerateRSA(attrs)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Generated RSA key: %v", key.Public())
}
```

### Multi-Backend Operations

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-keychain/internal/server"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
    // Initialize with multiple backends
    config := &server.BackendFactoryConfig{
        DefaultBackend: "pkcs8",
        Backends: []server.BackendConfig{
            {
                Name:    "pkcs8",
                Type:    "pkcs8",
                Enabled: true,
                Config: map[string]interface{}{
                    "key_dir": "./keys/pkcs8",
                },
            },
            {
                Name:    "aes",
                Type:    "aes",
                Enabled: true,
                Config: map[string]interface{}{
                    "key_dir": "./keys/aes",
                },
            },
        },
    }

    err := server.Initialize(config)
    if err != nil {
        log.Fatal(err)
    }
    defer keychain.Close()

    // Get specific backend
    aesBackend, err := keychain.Backend("aes")
    if err != nil {
        log.Fatal(err)
    }

    // Generate symmetric key
    attrs := &types.KeyAttributes{
        CN:                 "my-encryption-key",
        KeyType:            types.KeyTypeEncryption,
        StoreType:          types.StorePKCS8,
        SymmetricAlgorithm: types.SymmetricAES256GCM,
    }

    _, err = aesBackend.GenerateSymmetricKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // List all keys across all backends
    allKeys, err := keychain.ListKeys()
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Total keys across all backends: %d", len(allKeys))

    // List backends
    backends := keychain.Backends()
    log.Printf("Available backends: %v", backends)
}
```

For more details, see [docs/symmetric-encryption.md](docs/symmetric-encryption.md).

### Certificate Management

```go
// Store a certificate
cert := &x509.Certificate{...}
if err := ks.SaveCert("example.com", cert); err != nil {
    log.Fatal(err)
}

// Retrieve a certificate
cert, err := ks.GetCert("example.com")
if err != nil {
    log.Fatal(err)
}

// Store a certificate chain
chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
if err := ks.SaveCertChain("example.com", chain); err != nil {
    log.Fatal(err)
}
```

---

## Architecture

### Package Structure

```
go-keychain/
├── pkg/
│   ├── storage/           # Storage interfaces
│   │   ├── file/          # File-based storage
│   │   └── memory/        # In-memory storage
│   │
│   ├── backend/           # Backend interface & types
│   │   ├── pkcs8/         # PKCS#8 file backend
│   │   ├── pkcs11/        # HSM backend
│   │   ├── awskms/        # AWS KMS backend
│   │   ├── gcpkms/        # GCP KMS backend
│   │   ├── azurekv/       # Azure Key Vault backend
│   │   └── vault/         # HashiCorp Vault backend
│   │
│   ├── tpm2/              # TPM2 implementation
│   │
│   ├── encoding/          # PKCS#8 & PEM encoding
│   ├── verification/      # Signature verification
│   ├── signing/           # Enhanced signer
│   ├── opaque/            # OpaqueKey wrapper
│   │
│   ├── keychain/          # Composite KeyStore
│   └── certstore/         # Certificate Store
│
├── examples/              # Usage examples
└── test/
    └── integration/       # Integration test suite (151 tests)
```

### Design Pattern

```
┌─────────────┐
│  KeyStore   │  Composite:
│             │  - Backend (keys)
│             │  - CertStorage (certificates)
└──────┬──────┘
       │
       ├──────> Backend Interface
       │        ├── PKCS#8 (file-based)
       │        ├── PKCS#11 (HSM)
       │        ├── TPM2
       │        ├── Cloud KMS (AWS/GCP/Azure)
       |        ├── HashiCorp Vault
       │        └── Custom implementation
       │
       └──────> CertificateStorage Interface
                ├── File storage
                ├── Memory Storage
                ├── go-objstore backends
                └── Custom implementation
```

---


## Examples

The `examples/` directory contains comprehensive usage examples:

- **basic/** - Key generation and storage
- **signing/** - Signing and verification
- **certificates/** - CA creation, certificate issuance, chain management
- **tls/** - TLS server and client setup
- **advanced/** - Key rotation, concurrent operations

See [examples/README.md](examples/README.md) for details.

---

## Security Considerations

### Password Protection

PKCS#8 backend supports password-protected key storage:

```go
attrs.Password = []byte("secure-password")
key, err := ks.GenerateRSA(attrs)
```

### Hardware-Backed Keys

For production environments, use HSM or TPM backends:

```go
// PKCS#11 (HSM)
backend, err := pkcs11.New(&pkcs11.Config{
    Library: "/usr/lib/softhsm/libsofthsm2.so",
    // ...
})

// TPM2
backend, err := tpm2.New(&tpm2.Config{
    Device: "/dev/tpmrm0",
    // ...
})
```

### Cloud KMS

For cloud deployments:

```go
// AWS KMS
backend, err := awskms.New(&awskms.Config{
    Region: "us-east-1",
    // ...
})

// GCP KMS
backend, err := gcpkms.New(&gcpkms.Config{
    ProjectID: "my-project",
    // ...
})

// Azure Key Vault
backend, err := azurekv.New(&azurekv.Config{
    VaultURL: "https://my-vault.vault.azure.net/",
    // ...
})

// HashiCorp Vault
backend, err := vault.New(&vault.Config{
    Address: "https://vault.example.com:8200",
    // ...
})
```

---

## Documentation

### API Documentation

Full API documentation is available via GoDoc:

```bash
go doc github.com/jeremyhahn/go-keychain/pkg/keychain
go doc github.com/jeremyhahn/go-keychain/pkg/backend
go doc github.com/jeremyhahn/go-keychain/pkg/certstore
```

### Detailed Guides

Comprehensive documentation is available in the [docs/](docs/) directory:

- [Getting Started Guide](docs/getting-started.md) - Step-by-step guide to using go-keychain
- [Certificate Management](docs/certificate-management.md) - Certificate storage modes and best practices
- [Backend Guide](docs/backends/) - Backend-specific configuration and usage
- [Storage Abstraction](docs/storage-abstraction.md) - Storage layer architecture
- [Testing Guide](docs/testing/) - Running tests and writing new tests
- [Build System](docs/build-system.md) - Build and deployment instructions

### Core Interfaces

**KeyStore** - Main interface for key and certificate operations:
```go
type KeyStore interface {
    // Key operations
    GenerateRSA(attrs *backend.KeyAttributes) (crypto.PrivateKey, error)
    GenerateECDSA(attrs *backend.KeyAttributes) (crypto.PrivateKey, error)
    GenerateEd25519(attrs *backend.KeyAttributes) (crypto.PrivateKey, error)
    GetKey(attrs *backend.KeyAttributes) (crypto.PrivateKey, error)
    DeleteKey(attrs *backend.KeyAttributes) error
    RotateKey(attrs *backend.KeyAttributes) (crypto.PrivateKey, error)

    // Certificate operations
    SaveCert(cn string, cert *x509.Certificate) error
    GetCert(cn string) (*x509.Certificate, error)
    DeleteCert(cn string) error

    // Crypto operations
    Signer(attrs *backend.KeyAttributes) (crypto.Signer, error)
    Decrypter(attrs *backend.KeyAttributes) (crypto.Decrypter, error)
}
```

**Backend** - Interface for key storage backends:
```go
type Backend interface {
    Type() StoreType
    Capabilities() Capabilities
    GenerateKey(attrs *KeyAttributes) (crypto.PrivateKey, error)
    GetKey(attrs *KeyAttributes) (crypto.PrivateKey, error)
    DeleteKey(attrs *KeyAttributes) error
    Signer(attrs *KeyAttributes) (crypto.Signer, error)
    Decrypter(attrs *KeyAttributes) (crypto.Decrypter, error)
    Close() error
}
```

---

## Contributing

This library focuses on cryptographic key and certificate management. Features outside this scope (like event systems, secrets management, or server infrastructure) should be implemented in consuming applications.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/jeremyhahn/go-keychain
cd go-keychain

# Install dependencies
go mod download

# Run unit tests
go test ./pkg/... -cover

# Run integration tests
go test -tags=integration ./test/integration/... -v
```

---

## License

[![AGPL-3.0](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

go-keychain is available under a **dual-license model**:

### Option 1: GNU Affero General Public License v3.0 (AGPL-3.0)

The open-source version of go-keychain is licensed under the [AGPL-3.0](LICENSE-AGPL-3.txt).

**What does this mean?**

- ✓ Free to use, modify, and distribute
- ✓ Perfect for open-source projects
- ⚠️ If you modify and deploy as a network service (SaaS), you **must** disclose your source code
- ⚠️ Derivative works must also be licensed under AGPL-3.0

The AGPL-3.0 requires that if you modify this software and provide it as a service over a network (including SaaS deployments), you must make your modified source code available under the same license.

### Option 2: Commercial License

If you wish to use go-keychain in proprietary software without the source disclosure requirements of AGPL-3.0, a commercial license is available from **Automate The Things, LLC**.

**Commercial License Benefits:**

- ✓ Use in closed-source applications
- ✓ No source code disclosure requirements
- ✓ Modify and keep changes private
- ✓ Professional support and SLA options
- ✓ Custom development available
- ✓ Legal protections and indemnification

**Contact for Commercial Licensing:**

For pricing and commercial licensing inquiries:

📧 licensing@automatethethings.com
<br/>
🌐 https://automatethethings.com

See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for more details.

### Choosing the Right License

| Use Case | Recommended License |
|----------|-------------------|
| Open-source projects | AGPL-3.0 |
| Internal use with source disclosure | AGPL-3.0 |
| SaaS/Cloud services (open-source) | AGPL-3.0 |
| Proprietary SaaS products | Commercial |
| Closed-source applications | Commercial |
| Embedded in commercial products | Commercial |
| Need professional support | Commercial |

---

**Copyright © 2025 Automate The Things, LLC. All rights reserved.**


## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn

