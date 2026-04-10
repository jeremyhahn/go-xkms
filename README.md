# go-xkms

[![Go Version](https://img.shields.io/badge/Go-1.25.6-blue.svg)](https://golang.org)
[![Version](https://img.shields.io/badge/version-v0.2.3--alpha-green.svg)](https://github.com/jeremyhahn/go-xkms/releases)
[![Tests](https://img.shields.io/badge/tests-151%20passing-brightgreen.svg)](test/integration)
[![Coverage](https://img.shields.io/badge/coverage-92.5%25-brightgreen.svg)](pkg)
[![Backends](https://img.shields.io/badge/backends-8-blue.svg)](#backend-support-)
[![AGPL-3.0 License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE-AGPL-3.txt)
[![Commercial License](https://img.shields.io/badge/license-Commercial-green.svg)](LICENSE-COMMERCIAL.md)

A secure cryptographic key and certificate management solution for on-prem, hybrid, and/or cloud.

## Features at a Glance

- **8 Production-Ready Backends**: Software, PKCS#11, TPM2, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, Phone
- **Complete Key Management**: Generate, store, retrieve, rotate, and delete keys (RSA, ECDSA, Ed25519, AES)
- **Symmetric Encryption**: AES-GCM (128/192/256-bit) with AEAD safety support across all backends
- **Certificate Operations**: Full X.509 certificate lifecycle including chains and CRL support
- **Crypto Operations**: Sign, verify, encrypt, decrypt with standard Go interfaces
- **Thread-Safe**: Safe for concurrent operations with proper synchronization
- **Well-Tested**: 92.5% unit test coverage with 151 passing integration tests
- **Pluggable Architecture**: Easy to add custom backends and storage implementations
- **Unified Service API**: Simple API that abstracts backend complexity

## Overview

**go-xkms** provides a unified interface for managing cryptographic keys and certificates across multiple backend types, from simple file-based storage to hardware security modules and cloud KMS services.

### Core Focus

- **Keys**: Generate, store, retrieve, rotate cryptographic keys
- **Certificates**: Manage X.509 certificates, chains, and CRLs
- **Backends**: Pluggable storage (PKCS#8, PKCS#11, TPM2, Cloud KMS)
- **Standards**: PKCS#8, PEM, X.509, CRL formats

### Design Principles

- **Clean Architecture**: Clear separation of concerns, interface-based design
- **Pluggable Backends**: Easy to add new storage types
- **Unified Service API**: Single API for all backends - no leaky abstractions
- **Thread-Safe**: Safe for concurrent operations
- **Well-Tested**: 92.5% unit test coverage, 151 passing integration tests
- **Production-Ready**: v0.2.0-alpha with 8 fully working backends
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

True backends support **all three** operation types: asymmetric, symmetric, and sealing.

| Backend | Asymmetric | Symmetric | Sealing | Description |
|---------|:----------:|:---------:|:-------:|-------------|
| **Software** | ✓ | ✓ | ✓ | File-based keys using PKCS#8 + AES/ChaCha20 |
| **PKCS#11** | ✓ | ✓ | ✓ | Hardware Security Modules |
| **TPM2** | ✓ | ✓ | ✓ | Trusted Platform Module |
| **AWS KMS** | ✓ | ✓ | ✓ | Amazon Key Management Service |
| **GCP KMS** | ✓ | ✓ | ✓ | Google Cloud KMS |
| **Azure Key Vault** | ✓ | ✓ | ✓ | Azure Key Vault |
| **HashiCorp Vault** | ✓ | ✓ | ✓ | Vault Transit Engine |

### Convenience Libraries

Building blocks and specialized cryptographic libraries:

| Package | Purpose | Operations |
|---------|---------|------------|
| **PKCS#8** | Asymmetric key operations | RSA, ECDSA, Ed25519, X25519 |
| **AES** | Symmetric encryption | AES-GCM (128/192/256-bit) |
| **Quantum** | Post-quantum cryptography | ML-KEM key encapsulation, ML-DSA signatures |
| **Threshold** | Secret sharing | Shamir's Secret Sharing, threshold signatures |
| **DKEK** | Device Key Encryption Key | Backend-agnostic key wrapping with Shamir's Secret Sharing |

---

## Client Interfaces

go-xkms provides **5 client interfaces** for accessing key and certificate operations:

| Interface | Protocol | Coverage | Status | Use Case |
|-----------|----------|----------|--------|----------|
| **REST** | HTTP/HTTPS | 100% (17/17) | Complete | Web services, language-agnostic |
| **gRPC** | gRPC/Protobuf | 100% (17/17) | Complete | High-performance RPC |
| **QUIC** | HTTP/3 over QUIC | 100% (17/17) | Complete | Low-latency, UDP-based |
| **CLI** | Command-line | 100% (17/17) | Complete | Interactive, scripts |
| **MCP** | JSON-RPC | 100% (17/17) | Complete | Model Context Protocol |

All interfaces expose the complete KeyStore API for keys and certificates. See [docs/api-parity.md](docs/api-parity.md) for detailed method coverage.

### Interface Examples

**CLI (Command Line):**
```bash
# Key Management
xkmsctl key generate --name my-key --type rsa --size 2048
xkmsctl key generate --name signing-key --type ecdsa --curve P-256
xkmsctl key generate --name ed-key --type ed25519
xkmsctl key list
xkmsctl key get my-key
xkmsctl key delete my-key
xkmsctl key rotate my-key

# Certificate Management
xkmsctl cert list
xkmsctl cert get my-key
xkmsctl cert delete my-key

# Admin Management (requires FIDO2 security key)
xkmsctl admin status
xkmsctl admin create admin@example.com --display-name "Admin"
xkmsctl admin list
xkmsctl admin get admin@example.com
xkmsctl admin disable admin@example.com
xkmsctl admin enable admin@example.com

# FIDO2 Operations
xkmsctl fido2 list        # List connected security keys
xkmsctl fido2 info        # Show device information

# Backend Information
xkmsctl backends          # List available backends
```

**REST API:**
```bash
# Generate a key
curl -X POST http://localhost:8443/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_id": "my-key", "key_type": "rsa", "key_size": 2048}'

# List keys
curl http://localhost:8443/api/v1/keys

# Get a key's public info
curl http://localhost:8443/api/v1/keys/my-key

# Sign data
curl -X POST http://localhost:8443/api/v1/keys/my-key/sign \
  -H "Content-Type: application/json" \
  -d '{"data": "SGVsbG8gV29ybGQ=", "hash": "sha256"}'

# Health check
curl http://localhost:8443/api/v1/health
```

**gRPC:**
```go
import pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"

conn, _ := grpc.Dial("localhost:9443", grpc.WithInsecure())
client := pb.NewXKMSServiceClient(conn)

// Generate key
resp, _ := client.GenerateKey(ctx, &pb.GenerateKeyRequest{
    KeyId:   "my-key",
    KeyType: pb.KeyType_KEY_TYPE_RSA,
    KeySize: 2048,
})

// List keys
keys, _ := client.ListKeys(ctx, &pb.ListKeysRequest{})
```

**MCP (Model Context Protocol - for AI assistants):**
```json
{"jsonrpc": "2.0", "method": "xkms.generateKey",
 "params": {"key_id": "my-key", "key_type": "rsa", "key_size": 2048}, "id": 1}

{"jsonrpc": "2.0", "method": "xkms.listKeys", "params": {}, "id": 2}

{"jsonrpc": "2.0", "method": "xkms.sign",
 "params": {"key_id": "my-key", "data": "base64data", "hash": "sha256"}, "id": 3}
```

**QUIC (HTTP/3 - low latency UDP-based):**
```bash
# Same REST API over QUIC/HTTP3
curl --http3 https://localhost:8444/api/v1/keys
curl --http3 https://localhost:8444/api/v1/health
```

---

## Installation

### As a Library

```bash
go get github.com/jeremyhahn/go-xkms
```

### As a Server

```bash
# Build the server and CLI
make build-server build-cli

# Copy binaries to system path
sudo cp bin/xkmsd bin/xkmsctl /usr/bin/
```

See [deploy/README.md](deploy/README.md) for systemd and OpenRC service installation.

---

## Server Quick Start

### 1. First-Time Setup

Before using go-xkms as a service, you must create an administrator account with a FIDO2 security key:

```bash
# Check if setup is required
xkmsctl admin status

# Create the first administrator (requires FIDO2 security key)
xkmsctl admin create admin@example.com --display-name "Admin User"
# Touch your security key when prompted...

# Verify the admin was created
xkmsctl admin list
```

**Requirements:**
- A FIDO2-compatible security key (YubiKey 5, SoloKey, Nitrokey, etc.)
- The security key must be connected via USB

### 2. Configure the Server

Create a configuration file at `/etc/xkms/config.yaml`:

```yaml
# Server configuration
server:
  host: "0.0.0.0"
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444

# Default backend
default: pkcs8

# Backend configurations
backends:
  pkcs8:
    enabled: true
    key_dir: /var/lib/xkms/keys
```

### 3. Start the Server

```bash
# Direct execution
xkmsd -config /etc/xkms/config.yaml

# Or via systemd (after installing service files)
sudo systemctl start xkms
```

### 4. Verify Server is Running

```bash
# REST API health check
curl http://localhost:8443/api/v1/health

# List keys via CLI
xkmsctl key list

# Generate a test key
xkmsctl key generate --name test-key --type rsa --size 2048
```

---

## Quick Start (Library Usage)

go-xkms provides two API patterns depending on your use case:

| API | Function | Use Case |
|-----|----------|----------|
| **`xkms.New()`** | Creates a single KeyStore instance | Libraries, embedded use, explicit resource management |
| **`xkms.Initialize()`** | Sets up global service with multiple backends | Server applications, multi-backend scenarios |

### Pattern 1: Direct KeyStore (Recommended for Libraries)

Use `xkms.New()` when you need a single keystore instance with explicit lifecycle management:

```go
package main

import (
    "crypto"
    "crypto/rand"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
    // 1. Create storage backends
    keyStorage, err := file.New("./keys")
    if err != nil {
        log.Fatal(err)
    }
    certStorage, err := file.New("./certs")
    if err != nil {
        log.Fatal(err)
    }

    // 2. Create the software backend (supports all operations: keys, encryption, sealing)
    backend, err := software.NewBackend(&software.Config{
        KeyStorage: keyStorage,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer backend.Close()

    // 3. Create the KeyStore
    ks, err := xkms.New(&xkms.Config{
        Backend:     backend,
        CertStorage: certStorage,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer ks.Close()

    // 4. Generate a key
    attrs := &types.KeyAttributes{
        CN:        "my-signing-key",
        KeyType:   types.KeyTypeSigning,
        StoreType: types.StoreSoftware,
        RSAAttributes: &types.RSAAttributes{
            KeySize: 2048,
        },
    }

    key, err := ks.GenerateRSA(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // 5. Use the key for signing
    signer, err := ks.Signer(attrs)
    if err != nil {
        log.Fatal(err)
    }

    data := []byte("Hello, World!")
    signature, err := signer.Sign(rand.Reader, data, crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Generated signature: %x...", signature[:16])
}
```

### Pattern 2: Global Service (Recommended for Servers)

Use `xkms.Initialize()` for server applications that need multiple backends with global access:

```go
package main

import (
    "crypto"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
    // 1. Create storage and backend
    keyStorage, _ := file.New("./keys")
    certStorage, _ := file.New("./certs")

    // Software backend supports asymmetric keys, symmetric encryption, and sealing
    softwareBackend, _ := software.NewBackend(&software.Config{KeyStorage: keyStorage})
    softwareKS, _ := xkms.New(&xkms.Config{
        Backend:     softwareBackend,
        CertStorage: certStorage,
    })

    // 2. Initialize the global service
    err := xkms.Initialize(&xkms.ServiceConfig{
        Backends: map[string]xkms.KeyStore{
            "software": softwareKS,
        },
        DefaultBackend: "software",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // 3. Use global functions - keys are referenced as "backend:keyid" or just "keyid" for default
    attrs := &types.KeyAttributes{
        CN:        "server-key",
        KeyType:   types.KeyTypeSigning,
        StoreType: types.StoreSoftware,
        RSAAttributes: &types.RSAAttributes{KeySize: 2048},
    }

    _, err = xkms.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Sign using the global service
    signature, err := xkms.Sign("server-key", []byte("data"), &xkms.SignOptions{
        Hash: crypto.SHA256,
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Signature: %x...", signature[:16])

    // List available backends
    backends := xkms.Backends()
    log.Printf("Available backends: %v", backends)
}
```

### Symmetric Encryption Example

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
    // Setup - software backend supports both asymmetric and symmetric operations
    keyStorage, _ := file.New("./keys")
    certStorage, _ := file.New("./certs")
    backend, _ := software.NewBackend(&software.Config{KeyStorage: keyStorage})
    defer backend.Close()

    ks, _ := xkms.New(&xkms.Config{
        Backend:     backend,
        CertStorage: certStorage,
    })
    defer ks.Close()

    // Generate AES-256-GCM key
    attrs := &types.KeyAttributes{
        CN:                 "encryption-key",
        KeyType:            types.KeyTypeEncryption,
        StoreType:          types.StoreSoftware,
        SymmetricAlgorithm: types.SymmetricAES256GCM,
    }

    _, err := ks.GenerateSymmetricKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data
    encrypter, err := ks.SymmetricEncrypter(attrs)
    if err != nil {
        log.Fatal(err)
    }

    plaintext := []byte("sensitive data")
    ciphertext, err := encrypter.Encrypt(plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt data
    decrypted, err := encrypter.Decrypt(ciphertext, nil)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Decrypted: %s", decrypted)
}
```

For more examples, see the [examples/](examples/) directory and [xkey/docs/usage/getting-started.md](xkey/docs/usage/getting-started.md).

---

## xKMS Service API

The `xkms` package provides a simplified service API that abstracts backend complexity. After initialization, you can use simple function calls without managing KeyStore instances directly.

### Service Functions Overview

```go
import "github.com/jeremyhahn/go-xkms/pkg/xkms"

// Initialization
xkms.Initialize(config)     // Initialize with backends
xkms.IsInitialized()        // Check if initialized
xkms.Close()                // Close all backends
xkms.Reset()                // Reset for testing

// Backend Access
xkms.GetBackend("pkcs8")    // Get specific backend
xkms.DefaultBackend()       // Get default backend
xkms.Backends()             // List all backend names

// Key Operations (use key references like "my-key" or "backend:my-key")
xkms.GenerateKey(attrs)              // Generate key on default backend
xkms.GenerateKeyWithBackend("tpm2", attrs)  // Generate on specific backend
xkms.KeyByID("my-key")               // Get key by ID
xkms.DeleteKey("my-key")             // Delete key
xkms.RotateKey("my-key")             // Rotate key
xkms.ListKeys()                      // List all keys
xkms.ListKeys("pkcs8")               // List keys from specific backend

// Crypto Operations
xkms.Signer("my-key")                // Get crypto.Signer
xkms.Decrypter("my-key")             // Get crypto.Decrypter
xkms.Sign("my-key", data, opts)      // Sign data
xkms.Verify("my-key", data, sig, opts)  // Verify signature

// Symmetric Encryption
xkms.GenerateSymmetricKey("aes", attrs)  // Generate symmetric key
xkms.GetSymmetricKey("my-aes-key")       // Get symmetric key
xkms.Encrypt("my-aes-key", data, opts)   // Encrypt data
xkms.Decrypt("my-aes-key", encrypted, opts)  // Decrypt data

// Certificate Operations
xkms.SaveCertificate("my-key", cert)
xkms.Certificate("my-key")
xkms.DeleteCertificate("my-key")
xkms.ListCertificates()
xkms.SaveCertificateChain("my-key", chain)
xkms.CertificateChain("my-key")
xkms.CertificateExists("my-key")

// TLS Operations
xkms.GetTLSCertificate("my-key")     // Get tls.Certificate

// Sealing Operations (hardware-backed encryption)
xkms.Seal(ctx, data, opts)           // Seal with default backend
xkms.SealWithBackend(ctx, "tpm2", data, opts)
xkms.Unseal(ctx, sealed, opts)       // Unseal data
xkms.CanSeal()                       // Check if sealing supported

// Import/Export Operations
xkms.GetImportParameters(backend, attrs, algorithm)
xkms.WrapKey(backend, keyMaterial, params)
xkms.UnwrapKey(backend, wrapped, params)
xkms.ImportKey(backend, attrs, wrapped)
xkms.ExportKey("my-key", algorithm)
xkms.CopyKey("source:my-key", "dest-backend", attrs)
```

### Key Reference Format

Keys can be referenced in two formats:
- `"my-key"` - Uses the default backend
- `"backend:my-key"` - Uses a specific backend (e.g., `"tpm2:signing-key"`)

### Complete Example: Key Generation and Signing

```go
package main

import (
    "crypto"
    "crypto/x509"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
    // 1. Setup storage and backend
    keyStorage, _ := file.New("./keys")
    certStorage, _ := file.New("./certs")
    backend, _ := software.NewBackend(&software.Config{KeyStorage: keyStorage})

    ks, _ := xkms.New(&xkms.Config{
        Backend:     backend,
        CertStorage: certStorage,
    })

    // 2. Initialize global service (for server applications)
    err := xkms.Initialize(&xkms.ServiceConfig{
        Backends:       map[string]xkms.KeyStore{"software": ks},
        DefaultBackend: "software",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // 3. Generate an RSA key
    attrs := &types.KeyAttributes{
        CN:           "my-signing-key",
        KeyType:      types.KeyTypeSigning,
        StoreType:    types.StoreSoftware,
        KeyAlgorithm: x509.RSA,
        RSAAttributes: &types.RSAAttributes{
            KeySize: 2048,
        },
    }

    key, err := xkms.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Generated key: %T", key)

    // 4. Sign some data
    data := []byte("Hello, World!")
    signature, err := xkms.Sign("my-signing-key", data, &xkms.SignOptions{
        Hash: crypto.SHA256,
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Signature: %x", signature[:16])

    // 5. Verify the signature
    err = xkms.Verify("my-signing-key", data, signature, &types.VerifyOpts{
        Hash: crypto.SHA256,
    })
    if err != nil {
        log.Fatal("Verification failed:", err)
    }
    log.Println("Signature verified!")
}
```

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
go-xkms/
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
│   ├── dkek/              # Device Key Encryption Key
│   │
│   ├── xkms/              # Composite KeyStore
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
                └── Custom adapters (interface compatible with go-objstore)
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
go doc github.com/jeremyhahn/go-xkms/pkg/xkms
go doc github.com/jeremyhahn/go-xkms/pkg/backend
go doc github.com/jeremyhahn/go-xkms/pkg/certstore
```

### Detailed Guides

Comprehensive documentation is available in the [docs/](docs/) directory:

- [Getting Started Guide](docs/getting-started.md) - Step-by-step guide to using go-xkms
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
git clone https://github.com/jeremyhahn/go-xkms
cd go-xkms

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

go-xkms is available under a **dual-license model**:

### Option 1: GNU Affero General Public License v3.0 (AGPL-3.0)

The open-source version of go-xkms is licensed under the [AGPL-3.0](LICENSE-AGPL-3.txt).

**What does this mean?**

- ✓ Free to use, modify, and distribute
- ✓ Perfect for open-source projects
- ⚠️ If you modify and deploy as a network service (SaaS), you **must** disclose your source code
- ⚠️ Derivative works must also be licensed under AGPL-3.0

The AGPL-3.0 requires that if you modify this software and provide it as a service over a network (including SaaS deployments), you must make your modified source code available under the same license.

### Option 2: Commercial License

If you wish to use go-xkms in proprietary software without the source disclosure requirements of AGPL-3.0, a commercial license is available from **Automate The Things, LLC**.

**Commercial License Benefits:**

- ✓ Use in closed-source applications
- ✓ No source code disclosure requirements
- ✓ Modify and keep changes private
- ✓ Professional support and SLA options
- ✓ Custom development available
- ✓ Legal protections and indemnification

**Contact for Commercial Licensing:**

For pricing and commercial licensing inquiries:

licensing@automatethethings.com
<br/>
https://automatethethings.com

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

**Copyright (c) 2025 Automate The Things, LLC. All rights reserved.**


## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn
