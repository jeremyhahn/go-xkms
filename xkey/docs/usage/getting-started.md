# Getting Started with go-xkms

## Overview

go-xkms is a comprehensive cryptographic key management library for Go that provides a unified interface across multiple storage backends. Whether you need software-based key storage for development, hardware security modules for production, or cloud-based key management for scalability, go-xkms offers a consistent API while leveraging the security features of each backend.

This guide covers three initialization patterns -- from the simplest auto-discovery mode to the full-control multi-backend setup and the client/server Go SDK.

## Installation

```bash
go get github.com/jeremyhahn/go-xkms
```

## Build Configuration

go-xkms uses build tags to enable conditional compilation of cryptographic backends. By default, **only the software backend is enabled**. You can selectively enable additional backends by setting their corresponding variables to 1.

### Default Build

```bash
# Builds with software backend only (default, minimal build)
go build ./...

# Or using Make
make build
```

### Enabling Backends

Use Makefile variables to enable specific backends:

```bash
# Build with PKCS#11 HSM support
make build WITH_PKCS11=1

# Build with software and hardware backends
make build WITH_PKCS11=1 WITH_TPM2=1

# Build with cloud providers
make build WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1

# Build with all backends
make build WITH_PKCS11=1 WITH_TPM2=1 WITH_AWS_KMS=1 WITH_GCP_KMS=1 WITH_AZURE_KV=1 WITH_VAULT=1
```

### Using Build Tags Directly

You can also use Go build tags directly:

```bash
# Build with all backends (default)
go build -tags "software tpm2 pkcs11 awskms gcpkms azurekv" ./...

# Build with only specific backends
go build -tags "software awskms" ./...

# Run tests with specific backends
go test -tags "software tpm2" ./...
```

### Backend Build Tags

| Backend | Build Tag | Default | Makefile Variable |
|---------|-----------|---------|-------------------|
| Software | `software` | Enabled | WITH_SOFTWARE=1 |
| TPM2 | `tpm2` | Disabled | WITH_TPM2=0 |
| PKCS#11 | `pkcs11` | Disabled | WITH_PKCS11=0 |
| AWS KMS | `awskms` | Disabled | WITH_AWS_KMS=0 |
| GCP KMS | `gcpkms` | Disabled | WITH_GCP_KMS=0 |
| Azure Key Vault | `azurekv` | Disabled | WITH_AZURE_KV=0 |
| HashiCorp Vault | `vault` | Disabled | WITH_VAULT=0 |

### Why Use Build Tags?

- **Reduced Binary Size**: Exclude backends you don't need
- **Faster Compilation**: Skip unused dependencies
- **Simplified Deployment**: Avoid cloud SDK dependencies for on-premise deployments
- **Security**: Minimize attack surface by excluding unused code

### Example: Cloud-Only Build

```bash
# Build for AWS deployment only (includes software and AWS KMS)
make build WITH_AWS_KMS=1
```

### Example: On-Premise Build

```bash
# Build for on-premise with hardware backends
make build WITH_PKCS11=1 WITH_TPM2=1
```

## Quick Start (Pattern A: Auto-Initialize)

The recommended way to get started. `AutoInitialize` discovers all compiled-in backends and sets them up automatically:

```go
package main

import (
    "crypto/elliptic"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // Discover what's compiled in
    backends := xkms.SupportedBackends()
    fmt.Println("Available backends:", backends) // e.g. [pkcs8 software symmetric tpm2]

    // Auto-initialize all compiled-in backends with defaults (in-memory storage)
    if err := xkms.AutoInitialize(nil); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Generate a key
    key, err := xkms.GenerateKey(&types.KeyAttributes{
        CN:           "my-signing-key",
        StoreType:    types.BackendType("software"),
        KeyAlgorithm: x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated key: %T\n", key)

    // Sign data using the key ID format: "backend:::keyname"
    sig, err := xkms.Sign("software:::my-signing-key", []byte("Hello, go-xkms!"), nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", sig)

    // Verify the signature
    if err := xkms.Verify("software:::my-signing-key", []byte("Hello, go-xkms!"), sig, nil); err != nil {
        log.Fatal(err)
    }
    fmt.Println("Signature verified")
}
```

### Auto-Initialize with Persistent Storage

Pass an `AutoConfig` to use file-backed storage instead of in-memory:

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir:        "/var/lib/xkms",
    DefaultBackend: "software",
})
defer xkms.Close()
```

### Auto-Initialize with Backend-Specific Configuration

Override configuration for individual backends:

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir: "/var/lib/xkms",
    BackendConfigs: map[xkms.BackendType]map[string]interface{}{
        xkms.BackendSoftware: {
            "key_dir": "/var/lib/xkms/software/keys",
        },
    },
})
defer xkms.Close()
```

## Multi-Backend Architecture (Pattern B: Manual Init)

For full control over which backends are initialized and how they are configured, use `Initialize` directly:

```go
package main

import (
    "crypto/elliptic"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func main() {
    // Create storage
    keyStore, err := file.New("/var/lib/xkms/keys")
    if err != nil {
        log.Fatal(err)
    }
    certStore, err := file.New("/var/lib/xkms/certs")
    if err != nil {
        log.Fatal(err)
    }

    // Create a software KeyProvider
    keyProvider, err := software.NewBackend(&software.Config{
        KeyStorage: keyStore,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Wrap in xkms.Backend (adds certificate storage, TLS, unified API)
    softwareBackend, err := xkms.New(&xkms.BackendConfig{
        Backend:     keyProvider,
        CertStorage: certStore,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Initialize the service with named backends
    err = xkms.Initialize(&xkms.ServiceConfig{
        Backends: map[string]xkms.Backend{
            "software": softwareBackend,
        },
        DefaultBackend: "software",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Use the service API (identical to Pattern A)
    key, err := xkms.GenerateKey(&types.KeyAttributes{
        CN:           "my-key",
        StoreType:    types.BackendType("software"),
        KeyAlgorithm: x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Key generated: %T\n", key)

    // Sign with string-based key ID
    sig, err := xkms.Sign("software:::my-key", []byte("data"), nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", sig)
}
```

### Multiple Backends

Register multiple backends and route operations by key ID prefix:

```go
err := xkms.Initialize(&xkms.ServiceConfig{
    Backends: map[string]xkms.Backend{
        "software": softwareBackend,
        "tpm2":     tpm2Backend,
        "awskms":   awsBackend,
    },
    DefaultBackend: "software",
})
defer xkms.Close()

// Route to specific backends using the key ID format
sig1, _ := xkms.Sign("software:::app-key", data, nil)
sig2, _ := xkms.Sign("tpm2:::device-key", data, nil)
sig3, _ := xkms.Sign("awskms:::cloud-key", data, nil)

// Or use KeyAttributes with StoreType for type-safe routing
key, _ := xkms.GenerateKey(&types.KeyAttributes{
    CN:           "new-key",
    StoreType:    types.BackendType("tpm2"),
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
})
```

## Go SDK - Client/Server (Pattern C)

For client/server deployments, use the Go SDK to connect to a running go-xkms server:

```go
package main

import (
    "context"
    "fmt"
    "log"

    xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func main() {
    ctx := context.Background()

    // Connect via URL (protocol auto-detected)
    client, err := xkms.NewFromURL("https://localhost:8443")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }

    // Generate a key
    resp, err := client.GenerateKey(ctx, &xkms.GenerateKeyRequest{
        KeyID:   "my-signing-key",
        Backend: "software",
        KeyType: "EC",
        Curve:   "P-256",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated key: %s\n", resp.KeyID)

    // Sign data
    signResp, err := client.Sign(ctx, &xkms.SignRequest{
        Backend: "software",
        KeyID:   "my-signing-key",
        Data:    []byte("Hello, World!"),
        Hash:    "SHA256",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature: %x\n", signResp.Signature)
}
```

### Supported Protocols

| Protocol | Scheme | Description |
|----------|--------|-------------|
| Unix Socket | `unix://` | Default, fastest for local |
| gRPC | `grpc://`, `grpcs://` | High-performance RPC |
| REST | `http://`, `https://` | HTTP/HTTPS REST API |
| QUIC | `quic://` | HTTP/3 over QUIC |
| Embedded | N/A | Direct in-process calls |

### Embedded Mode (In-Process)

For applications that need the full `XKMSServicer` interface without a network server, use the embedded transport. This is how the xkey GUI manages local keys:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/xkms"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
    "github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func main() {
    ctx := context.Background()

    // Initialize with persistent storage
    if err := xkms.AutoInitialize(&xkms.AutoConfig{
        DataDir:        "/var/lib/myapp/keys",
        DefaultBackend: "software",
    }); err != nil {
        log.Fatal(err)
    }
    defer xkms.Close()

    // Get the XKMSService singleton (implements XKMSServicer)
    svc, err := xkms.Get()
    if err != nil {
        log.Fatal(err)
    }

    // Create an embedded client — no network, direct in-process calls
    client, err := xkmssdk.NewEmbedded(svc)
    if err != nil {
        log.Fatal(err)
    }

    // Use the same SDK Client interface as remote clients
    resp, err := client.GenerateKey(ctx, &transport.GenerateKeyRequest{
        KeyID:   "my-local-key",
        Backend: "software",
        KeyType: "EC",
        Curve:   "P-256",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated local key: %s\n", resp.KeyID)
}
```

See the [Go SDK README](../../sdk/go/README.md) for full SDK documentation.

## Service API Reference

Once initialized (via any pattern), the `xkms` package exposes these top-level functions:

### Key Operations

| Function | Description |
|----------|-------------|
| `xkms.GenerateKey(attrs)` | Generate a new key (routes by `StoreType`) |
| `xkms.Key(attrs)` | Retrieve a key by attributes |
| `xkms.KeyByID(kid)` | Retrieve a key by string key ID |
| `xkms.DeleteKey(attrs)` | Delete a key by attributes |
| `xkms.DeleteKeyByID(kid)` | Delete a key by string key ID |
| `xkms.ListKeys(backend...)` | List keys (optionally filtered by backend) |
| `xkms.RotateKey(kid)` | Rotate an existing key |

### Signing and Verification

| Function | Description |
|----------|-------------|
| `xkms.Sign(kid, data, opts)` | Sign data (hashes automatically) |
| `xkms.Verify(kid, data, sig, opts)` | Verify a signature |
| `xkms.Signer(attrs)` | Get a `crypto.Signer` for a key |

### Symmetric Encryption

| Function | Description |
|----------|-------------|
| `xkms.GenerateSymmetricKey(backend, attrs)` | Generate a symmetric key |
| `xkms.Encrypt(kid, data, opts)` | Encrypt data with symmetric key |
| `xkms.Decrypt(kid, data, opts)` | Decrypt data with symmetric key |

### Certificate Operations

| Function | Description |
|----------|-------------|
| `xkms.Certificate(attrs)` | Get a certificate by attributes |
| `xkms.CertificateByID(kid)` | Get a certificate by key ID |
| `xkms.SaveCertificate(attrs, cert)` | Save a certificate |
| `xkms.SaveCertificateByID(kid, cert)` | Save a certificate by key ID |
| `xkms.DeleteCertificate(attrs)` | Delete a certificate |
| `xkms.CertificateChain(attrs)` | Get a certificate chain |
| `xkms.SaveCertificateChain(attrs, chain)` | Save a certificate chain |
| `xkms.TLSCertificate(attrs)` | Get a `tls.Certificate` for TLS use |
| `xkms.ListCertificates(backend...)` | List certificate IDs |

### Import/Export

| Function | Description |
|----------|-------------|
| `xkms.ExportKey(kid, algorithm)` | Export a key in wrapped form |
| `xkms.ImportKey(backend, attrs, wrapped)` | Import wrapped key material |
| `xkms.CopyKey(sourceKID, destBackend, attrs)` | Copy a key between backends |
| `xkms.GetImportParameters(backend, attrs, algo)` | Get import parameters |
| `xkms.WrapKey(backend, material, params)` | Wrap key material |

### Sealing (TPM2/Hardware)

| Function | Description |
|----------|-------------|
| `xkms.Seal(ctx, data, opts)` | Seal data with default backend |
| `xkms.SealWithBackend(ctx, name, data, opts)` | Seal with a specific backend |
| `xkms.Unseal(ctx, sealed, opts)` | Unseal previously sealed data |
| `xkms.CanSeal(backend...)` | Check if sealing is supported |

### Backend Discovery

| Function | Description |
|----------|-------------|
| `xkms.SupportedBackends()` | List compiled-in backend types |
| `xkms.IsBackendSupported(name)` | Check if a backend is compiled in |
| `xkms.BackendCount()` | Count available backends |
| `xkms.GetBackend(name)` | Get a specific backend instance |
| `xkms.GetBackendInfo(name)` | Get backend metadata and capabilities |
| `xkms.Backends()` | List names of initialized backends |

### Key ID Format

The string-based API uses a 4-part key ID format: `backend:type:algo:keyname`

All segments except `keyname` are optional:
- `"my-key"` -- uses the default backend
- `"software:::my-key"` -- routes to the `software` backend
- `"tpm2:signing:ecdsa-p256:my-key"` -- fully qualified

## Choosing a Backend

### Decision Tree

```
+---------------------------------+
| What is your primary use case?  |
+----------------+----------------+
                 |
        +--------+--------+
        |                 |
        v                 v
Development/     Production
Testing          Workload
        |                 |
        v                 v
Software         Security Level?
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
     Software    Moderate      High
     Based       Security    Security
          |           |           |
          v           v           v
     Software       TPM2       PKCS#11
                              Cloud HSM
                              (AWS/GCP/Azure)
```

### Backend Comparison Matrix

| Feature | Software | TPM2 | PKCS#11 | AWS KMS | GCP KMS | Azure KV |
|---------|----------|------|---------|---------|---------|----------|
| **Security Level** | Software | Hardware | Hardware | Cloud HSM | Cloud HSM | Cloud HSM |
| **FIPS 140-2** | No | Level 2 | Level 2/3 | Level 2/3 | Level 3 | Level 2/3 |
| **Key Export** | Yes | No | No | No | No | No |
| **Offline Use** | Yes | Yes | Yes | No | No | No |
| **Cost** | Free | Free | $100-$10k+ | $1/key/mo | ~0.06/key/mo | $1/key/mo |
| **Setup Complexity** | Low | Medium | High | Low | Low | Low |
| **Performance** | Fastest | Fast | Fast | Network | Network | Network |
| **Best For** | Dev/Test | Desktop/Edge/IoT | Enterprise | AWS Cloud | GCP Cloud | Azure Cloud |

## Backend Configuration Reference

The following sections document backend-specific configuration for Pattern B (manual init) users. Pattern A users can pass backend-specific settings via `AutoConfig.BackendConfigs`.

### Software - Unified Software Backend

The software backend provides both asymmetric (RSA, ECDSA, Ed25519 via PKCS#8 encoding) and symmetric (AES-GCM, ChaCha20-Poly1305) operations through a single unified interface.

**When to use:**
- Development and testing
- CI/CD pipelines
- Low-security requirements
- Offline operation needed

**Manual Setup (Pattern B):**
```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

keyStorage, err := file.New("/var/lib/xkms/keys")
certStorage, err := file.New("/var/lib/xkms/certs")

keyProvider, err := software.NewBackend(&software.Config{
    KeyStorage: keyStorage,
})

store, err := xkms.New(&xkms.BackendConfig{
    Backend:     keyProvider,
    CertStorage: certStorage,
})
```

**Learn More:** [Software Backend Documentation](../backends/software.md)

### TPM 2.0 - Hardware-Backed On-Premise

**When to use:**
- Desktop/Laptop/Server/Edge devices with TPM chips
- IoT deployments
- On-premise servers
- Air-gapped environments

**Manual Setup (Pattern B):**
```go
config := &tpm2.Config{
    CN:         "my-xkms",
    DevicePath: "/dev/tpmrm0",
    SRKHandle:  0x81000001,
}
store, err := tpm2.NewBackend(config, backend)
```

**Learn More:** [TPM2 Documentation](../backends/tpm2.md)

### PKCS#11 - Enterprise HSM

**When to use:**
- Enterprise data centers
- Regulatory compliance (PCI DSS, HIPAA)
- Certificate authorities
- High-security applications

**Manual Setup (Pattern B):**
```go
config := &pkcs11.Config{
    LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel:  "my-token",
    PIN:         os.Getenv("HSM_PIN"),
}
store, err := pkcs11.NewBackend(config)
```

**Learn More:** [PKCS#11 Documentation](../backends/pkcs11.md)

### AWS KMS - Amazon Cloud HSM

**When to use:**
- AWS-hosted or hybrid applications
- Multi-region deployments
- Scalable cloud workloads

**Manual Setup (Pattern B):**
```go
config := &awskms.Config{
    Region: "us-east-1",
    // Uses IAM role automatically
}
store, err := awskms.NewBackend(config)
```

**Learn More:** [AWS KMS Documentation](../backends/awskms.md)

### GCP KMS - Google Cloud HSM

**When to use:**
- GCP-hosted or hybrid applications
- Global deployments
- FIPS 140-2 Level 3 required

**Manual Setup (Pattern B):**
```go
config := &gcpkms.Config{
    ProjectID: "my-project",
    Location:  "us-central1",
    KeyRing:   "production",
}
store, err := gcpkms.NewBackend(config)
```

**Learn More:** [GCP KMS Documentation](../backends/gcpkms.md)

### Azure Key Vault - Microsoft Cloud HSM

**When to use:**
- Azure-hosted or hybrid applications
- Microsoft ecosystem integration
- Managed HSM requirements

**Manual Setup (Pattern B):**
```go
config := &azurekv.Config{
    VaultURL:           "https://my-vault.vault.azure.net/",
    UseManagedIdentity: true,
}
store, err := azurekv.NewBackend(config)
```

**Learn More:** [Azure Key Vault Documentation](../backends/azurekv.md)

## Common Use Cases

### Development Environment

Use auto-initialize with in-memory storage:

```go
if err := xkms.AutoInitialize(nil); err != nil {
    log.Fatal(err)
}
defer xkms.Close()

// All operations use in-memory storage, no files created
key, _ := xkms.GenerateKey(&types.KeyAttributes{
    CN:           "dev-key",
    StoreType:    types.BackendType("software"),
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
})
```

### Production Application (Cloud)

Use auto-initialize with persistent storage:

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir:        "/var/lib/xkms",
    DefaultBackend: "awskms",
})
defer xkms.Close()

// Sign with cloud-managed keys
sig, _ := xkms.Sign("awskms:::prod-signing-key", data, nil)
```

### Edge Device / IoT

Use auto-initialize with TPM2 as default:

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir:        "/var/lib/xkms",
    DefaultBackend: "tpm2",
})
defer xkms.Close()

// Keys are hardware-backed
key, _ := xkms.GenerateKey(&types.KeyAttributes{
    CN:           "device-identity",
    StoreType:    types.BackendType("tpm2"),
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
})
```

### Multi-Backend Hybrid

Combine backends for different security levels:

```go
// Build with: make build WITH_PKCS11=1 WITH_AWS_KMS=1
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir:        "/var/lib/xkms",
    DefaultBackend: "software",
})
defer xkms.Close()

// Use the right backend for each key's security requirements
appKey, _ := xkms.GenerateKey(&types.KeyAttributes{
    CN:        "app-session-key",
    StoreType: types.BackendType("software"),
    // ...
})

caKey, _ := xkms.GenerateKey(&types.KeyAttributes{
    CN:        "ca-signing-key",
    StoreType: types.BackendType("pkcs11"),
    // ...
})
```

## Key Management Patterns

### Key Generation

```go
// ECDSA key
ecKey, err := xkms.GenerateKey(&types.KeyAttributes{
    CN:           "ec-signing-key",
    StoreType:    types.BackendType("software"),
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
})

// RSA key
rsaKey, err := xkms.GenerateKey(&types.KeyAttributes{
    CN:           "rsa-encryption-key",
    StoreType:    types.BackendType("software"),
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &types.RSAAttributes{KeySize: 2048},
})

// Ed25519 key
edKey, err := xkms.GenerateKey(&types.KeyAttributes{
    CN:           "ed25519-signing-key",
    StoreType:    types.BackendType("software"),
    KeyAlgorithm: x509.Ed25519,
})
```

### Signing Operations

```go
// Sign (hashing is handled automatically)
sig, err := xkms.Sign("software:::my-key", document, nil)

// Sign with specific options
sig, err := xkms.Sign("software:::my-key", document, &xkms.SignOptions{
    Hash: crypto.SHA512,
})

// Verify
err = xkms.Verify("software:::my-key", document, sig, nil)
```

### Key Rotation

```go
// Rotate replaces the key with a new one of the same type
newKey, err := xkms.RotateKey("software:::my-key")
```

### Listing Keys

```go
// List all keys across all backends
allKeys, err := xkms.ListKeys()

// List keys from a specific backend
softwareKeys, err := xkms.ListKeys("software")
```

## Symmetric Encryption

All backends support AES-GCM symmetric encryption with AEAD support.

### Generate and Use Symmetric Keys

```go
// Generate a symmetric key
symKey, err := xkms.GenerateSymmetricKey("software", &types.KeyAttributes{
    CN:           "my-encryption-key",
    KeyType:      types.KEY_TYPE_ENCRYPTION,
    StoreType:    types.BackendType("software"),
    KeyAlgorithm: types.ALG_AES256_GCM,
    AESAttributes: &types.AESAttributes{KeySize: 256},
})

// Encrypt
encrypted, err := xkms.Encrypt("software:::my-encryption-key", plaintext, &types.EncryptOptions{
    AdditionalData: []byte("context"),
})

// Decrypt
decrypted, err := xkms.Decrypt("software:::my-encryption-key", encrypted, &types.DecryptOptions{
    AdditionalData: []byte("context"),
})
```

### Symmetric Key Algorithms

| Algorithm | Key Size | Mode | Features |
|-----------|----------|------|----------|
| AES-GCM | 128-bit | Galois/Counter Mode | AEAD, authenticated encryption |
| AES-GCM | 192-bit | Galois/Counter Mode | AEAD, authenticated encryption |
| AES-GCM | 256-bit | Galois/Counter Mode | AEAD, authenticated encryption |

## Testing

### Running Tests

```bash
# Run all unit tests (fast, no system modifications)
make test

# Run all integration tests (Docker-based)
make integration-test

# Run specific backend integration tests
make integration-test-software
make integration-test-tpm2
make integration-test-pkcs11
make integration-test-awskms
make integration-test-gcpkms
make integration-test-azurekv
make integration-test-vault
```

### Test Structure

Integration tests are organized in `test/integration/backend/`:

```
test/integration/
├── backend/
│   ├── software_integration_test.go  # Software backend tests
│   ├── tpm2_integration_test.go      # TPM2 simulator tests
│   └── symmetric_integration_test.go # Symmetric encryption tests
├── pkcs11/             # PKCS#11/SoftHSM tests
├── awskms/             # AWS KMS/LocalStack tests
├── gcpkms/             # GCP KMS mock tests
├── azurekv/            # Azure Key Vault mock tests
└── vault/              # HashiCorp Vault tests
```

## Error Handling Best Practices

### Comprehensive Error Handling

```go
err := xkms.AutoInitialize(nil)
if err != nil {
    switch {
    case errors.Is(err, xkms.ErrNoBackendsAvailable):
        log.Fatal("no backends compiled in -- check build tags")
    default:
        log.Fatalf("initialization failed: %v", err)
    }
}
defer xkms.Close()

key, err := xkms.GenerateKey(attrs)
if err != nil {
    switch {
    case errors.Is(err, xkms.ErrNotInitialized):
        log.Fatal("call xkms.AutoInitialize() first")
    case errors.Is(err, xkms.ErrBackendNotFound):
        log.Fatal("backend not available -- check build tags")
    default:
        log.Fatalf("key generation failed: %v", err)
    }
}
```

## Security Best Practices

### Password Management

```go
// Bad: Hardcoded secrets
config := &software.Config{
    KeyStorage: keyStorage, // NEVER hardcode secrets
}

// Good: Environment variable
password := os.Getenv("KEYSTORE_PASSWORD")

// Better: Secret management service
func loadPassword() string {
    // Load from HashiCorp Vault, AWS Secrets Manager, etc.
    return secretsClient.GetSecret("xkms-password")
}
```

### Access Control

```go
// Principle of least privilege
func configureCloudKMS() *awskms.Config {
    return &awskms.Config{
        Region: "us-east-1",
        // Uses IAM role with minimal permissions:
        // - kms:Sign
        // - kms:Verify
        // - kms:GetPublicKey
    }
}
```

## Troubleshooting

### Common Issues

**Issue: "no backends available"**
```
Build with backend tags enabled:
  make build WITH_PKCS11=1 WITH_TPM2=1
Or check compiled backends:
  fmt.Println(xkms.SupportedBackends())
```

**Issue: "service not initialized"**
```go
// Solution: Call AutoInitialize or Initialize before any operation
if err := xkms.AutoInitialize(nil); err != nil {
    log.Fatal(err)
}
```

**Issue: "backend not found"**
```go
// Solution: Check available backends
fmt.Println("Available:", xkms.Backends())
// Ensure the backend was compiled in
fmt.Println("Supported:", xkms.SupportedBackends())
```

**Issue: Key Not Found**
```go
// Solution: List keys to verify what exists
keys, _ := xkms.ListKeys("software")
for _, k := range keys {
    fmt.Println(k.CN)
}
```

**Issue: Permission Denied (Cloud)**
```
// AWS KMS: Check IAM policy and key policy
// GCP KMS: Verify service account has cloudkms.signerVerifier role
// Azure KV: Check RBAC assignment or access policy
```

## Server Bootstrap

For client/server deployments, go-xkms uses a secure bootstrap workflow that establishes trust without relying on pre-existing PKI infrastructure.

### End-to-End Flow

```
1. Server first boot    -->  Prints setup token + SPKI pin
2. Admin registers      -->  xkey auth register --server URL --spki-pin PIN
3. Custodian group      -->  xkmsctl custodian create --name "Ops" --threshold 3 --total 5
4. Members added        -->  xkmsctl custodian add-member --group-id G --user-id U
5. Shares distributed   -->  xkmsctl custodian distribute --group-id G
6. Custodians receive   -->  xkey share receive --server URL
7. Barrier unsealed     -->  xkey share unseal --server URL --group-id G  (x3)
8. Client cert enrolled -->  xkey cert request --server URL --cn "user@example.com"
```

### Step 1: Server First Boot

On first start, the server generates a one-time setup token and prints its SPKI pin:

```
Setup Token:  eyJhbGciOi...  (one-time use, 15 min TTL)
SPKI Pin:     e5f6a7b8c9d0e1f2...
Hostname:     kms.example.com:8443
```

### Step 2: Admin Registration with SPKI Pin

The first admin registers using the SPKI pin for trust-on-first-use:

```bash
xkey auth register --server https://kms.example.com:8443 --spki-pin e5f6a7b8...
```

### Step 3: Custodian Setup and Share Distribution

Create a custodian group and distribute Shamir shares:

```bash
xkmsctl custodian create --name "Production Ops" --threshold 3 --total 5
xkmsctl custodian add-member --group-id G --user-id user-1
xkmsctl custodian add-member --group-id G --user-id user-2
# ... add remaining members
xkmsctl custodian distribute --group-id G
```

### Step 4: Barrier Unsealing

Each custodian receives their share and submits it to unseal the barrier:

```bash
xkey share receive --server grpc://kms.example.com:9090
xkey share unseal --server grpc://kms.example.com:9090 --group-id G
```

Once the threshold is reached, the barrier is unsealed and key operations resume.

### Step 5: Client Certificate Enrollment

With the barrier unsealed, enroll a client certificate for mTLS:

```bash
xkey cert request --server https://kms.example.com:8443 --cn "alice@example.com"
```

See the [Bootstrap Architecture](../bootstrap/README.md) for protocol details on DANE, Noise, and SPKI trust methods.

## Next Steps

- Review backend-specific documentation for detailed configuration
- Set up monitoring and alerting
- Plan key rotation policies
- Test disaster recovery procedures
- Explore the [Go SDK](../../sdk/go/README.md) for client/server deployments

## Additional Resources

- [Software Backend Documentation](../backends/software.md)
- [TPM2 Backend Documentation](../backends/tpm2.md)
- [PKCS#11 Backend Documentation](../backends/pkcs11.md)
- [AWS KMS Backend Documentation](../backends/awskms.md)
- [GCP KMS Backend Documentation](../backends/gcpkms.md)
- [Azure Key Vault Backend Documentation](../backends/azurekv.md)
- [Go SDK README](../../sdk/go/README.md)

## Support

For issues, questions, or contributions, please visit the GitHub repository.
