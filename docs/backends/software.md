# Software Backend

## Overview

The Software backend is the default, full-featured backend for go-xkms. It provides both asymmetric and symmetric cryptographic operations using software-based implementations, making it suitable for development, testing, CI/CD pipelines, and production environments where hardware security modules are not required.

Internally, the Software backend uses a Composite/Facade design pattern:
- **Asymmetric operations** (RSA, ECDSA, Ed25519) are delegated to the PKCS#8 subsystem
- **Symmetric operations** (AES-GCM, ChaCha20-Poly1305) are handled by the symmetric subsystem

This design provides a consistent full-service interface similar to hardware and cloud backends (TPM 2.0, AWS KMS, etc.) which also support both operation types through a single KeyProvider.

## Features and Capabilities

### Asymmetric Operations
- Key generation, signing, and verification
- Public key export
- Key identifier management
- PKCS#8 encrypted private key storage on disk

### Symmetric Operations
- AES-GCM (128/192/256-bit) authenticated encryption
- ChaCha20-Poly1305 authenticated encryption
- AEAD safety tracking (nonce reuse prevention, bytes-before-rekey limits)

### Supported Algorithms

#### RSA
- Key sizes: 2048, 3072, 4096, 6144, 8192 bits
- Signature schemes: PKCS#1 v1.5, PSS
- Hash functions: SHA-256, SHA-384, SHA-512

#### ECDSA
- Curves: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
- Hash functions: SHA-256, SHA-384, SHA-512

#### Ed25519
- Edwards-curve Digital Signature Algorithm
- Fixed 256-bit keys
- Native Ed25519 signatures

#### AES-GCM (Symmetric)
- Key sizes: 128, 192, 256 bits
- Galois/Counter Mode with authenticated encryption
- Additional authenticated data (AAD) support

#### ChaCha20-Poly1305 (Symmetric)
- 256-bit keys
- AEAD with Poly1305 MAC
- Suitable for environments without AES hardware acceleration

## Service Integration

### Build Tag

No build tag required. The software backend is always compiled into the binary and auto-registers with the xkms service registry at init time.

### Checking Availability

```go
import "github.com/jeremyhahn/go-xkms/pkg/xkms"

if xkms.IsBackendSupported(xkms.BackendSoftware) {
    fmt.Println("Software backend is available")
}

// List all compiled-in backends
for _, b := range xkms.SupportedBackends() {
    fmt.Println("  ", b)
}
```

### Using via Service API

```go
import (
    "crypto/elliptic"
    "crypto/x509"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Generate a key on the software backend
key, err := xkms.GenerateKeyWithBackend("software", &types.KeyAttributes{
    CN:           "my-signing-key",
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{
        Curve: elliptic.P256(),
    },
})

// Sign using the key ID (software is the default backend)
sig, err := xkms.Sign("my-signing-key", data, nil)

// Or specify the backend explicitly in the key ID
sig, err = xkms.Sign("software:::my-signing-key", data, nil)
```

### Auto-Initialize

The software backend is the default for `AutoInitialize`. When no configuration is provided, it uses in-memory storage.

```go
// Minimal initialization (software backend with in-memory storage)
err := xkms.AutoInitialize(nil)
defer xkms.Close()

// With persistent storage
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir: "/var/lib/xkms",
})
defer xkms.Close()
```

## Configuration

### Config Structure

```go
type Config struct {
    // KeyStorage is the underlying storage for key material.
    // This can be file-based, memory-based, or any implementation
    // of the storage.Backend interface.
    //
    // The same storage is used for both asymmetric and symmetric keys,
    // which are differentiated by their key IDs.
    KeyStorage storage.Backend

    // Tracker is the AEAD safety tracker for nonce/bytes tracking.
    // If nil, a default memory-based tracker will be created.
    // For production systems, provide a persistent tracker.
    Tracker types.AEADSafetyTracker
}
```

### Configuration Parameters

**KeyStorage** (required)
- Storage backend for key material (file-based, memory-based, etc.)
- Implements the `storage.Backend` interface
- The same storage instance handles both asymmetric and symmetric keys

**Tracker** (optional)
- AEAD safety tracker for nonce reuse prevention and bytes-before-rekey enforcement
- If nil, a default in-memory tracker is created
- For production use, provide a persistent tracker to survive restarts

## Usage

### Standalone KeyProvider

Use the Software backend directly when you only need key operations:

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// Create storage
store, err := file.New("/var/lib/xkms/keys")

// Create the Software KeyProvider
keyProvider, err := software.NewBackend(&software.Config{
    KeyStorage: store,
})
defer keyProvider.Close(ctx)
```

### Full Service Interface (Recommended)

Wrap the Software KeyProvider in `xkms.Backend` for the complete service interface with certificate storage, TLS helpers, and unified key IDs:

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/backend/software"
    "github.com/jeremyhahn/go-xkms/pkg/storage/file"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Create key and certificate storage
keyStorage, err := file.New("/var/lib/xkms/keys")
certStorage, err := file.New("/var/lib/xkms/certs")

// Create the Software KeyProvider
keyProvider, err := software.NewBackend(&software.Config{
    KeyStorage: keyStorage,
})

// Wrap in xkms.Backend for full service interface
backend, err := xkms.New(&xkms.BackendConfig{
    Backend:     keyProvider,
    CertStorage: certStorage,
})

// Use the full-service backend
key, err := backend.GenerateRSA(ctx, attrs)
cert, err := backend.StoreCertificate(ctx, certData)
```

## Security Considerations

### Storage Security
- Private keys are stored encrypted using PKCS#8 EncryptedPrivateKeyInfo
- Use restrictive file permissions (0700) on the storage directory
- Consider encrypted filesystems for additional protection

### AEAD Safety
- The symmetric subsystem tracks nonce usage and encrypted bytes to prevent reuse
- In production, use a persistent tracker to maintain safety state across restarts
- The tracker enforces rekeying before cryptographic limits are reached

### When to Use Hardware Backends
The Software backend stores keys in software and memory. For environments requiring:
- Hardware-protected key storage: Use [TPM 2.0](tpm2.md) or [PKCS#11](pkcs11.md)
- Cloud-managed keys: Use [AWS KMS](awskms.md), [GCP KMS](gcpkms.md), or [Azure Key Vault](azurekv.md)
- FIPS 140-2 compliance: Use hardware or cloud backends

## Limitations

- Keys are software-based, not hardware-protected
- Private keys exist in memory during operations
- No FIPS 140-2 compliance without additional modules
- File system security depends on OS-level controls

## See Also

- [Backend Selection Guide](README.md)
- [Symmetric Encryption Architecture](../architecture/symmetric-encryption.md)
- [AEAD Configuration](../configuration/aead-auto-selection.md)
- [Getting Started](../usage/getting-started.md)
