# PKCS#8 Backend Documentation

## Overview

The PKCS#8 backend provides software-based key storage using the industry-standard PKCS#8 private key format. Keys are encoded in PKCS#8 DER format and stored via a pluggable `storage.Backend` interface (in-memory, file-based, or custom). When a password is provided on the key attributes, the private key is encrypted using the `github.com/youmark/pkcs8` library (PBKDF2 + AES).

PKCS#8 (Public-Key Cryptography Standards #8) is a standard syntax for storing private key information. The go-xkms PKCS#8 backend implements the `types.KeyProvider`, `types.KeyAgreement`, and `types.Sealer` interfaces.

## Features and Capabilities

The backend reports the following `types.Capabilities`:

| Capability            | Supported |
|-----------------------|-----------|
| Keys                  | Yes       |
| HardwareBacked        | No        |
| Signing               | Yes       |
| Decryption            | Yes       |
| KeyRotation           | Yes       |
| SymmetricEncryption   | No        |
| Import                | Yes       |
| Export                | Yes       |
| KeyAgreement          | Yes       |
| ECIES                 | No        |

### Supported Algorithms

**RSA** - Key sizes 2048+ bits (minimum enforced). Supports PKCS#1 v1.5 and PSS signatures.

**ECDSA** - Curves P-256, P-384, P-521.

**Ed25519** - Fixed 256-bit Edwards-curve keys.

**X25519** - Key agreement via `X25519Attributes` on `KeyAttributes`.

### Sealing

The backend implements `types.Sealer` using HKDF-derived AES-256-GCM. A sealing key is derived from the private key material via HKDF-SHA256, then data is encrypted with AES-GCM using a random nonce. This is software-only sealing; for hardware-bound secrets, use TPM or HSM backends.

## Configuration

### Config Structure

```go
// Config contains configuration for the PKCS8Backend.
type Config struct {
    // KeyStorage is the underlying storage for key material.
    // This can be file-based, memory-based, or any implementation
    // of the storage.Backend interface.
    KeyStorage storage.Backend
}
```

The `KeyStorage` field is required. Passing a nil `KeyStorage` causes `Validate()` to return an error.

### Constructor

```go
func NewBackend(config *Config) (types.KeyProvider, error)
```

Returns a `*PKCS8Backend` (as `types.KeyProvider`) or an error if validation fails.

## Complete Working Example

```go
package main

import (
    "crypto"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
    // Create an in-memory storage backend
    memStore := storage.NewMemory()

    // Initialize the PKCS#8 backend
    config := &pkcs8.Config{
        KeyStorage: memStore,
    }

    backend, err := pkcs8.NewBackend(config)
    if err != nil {
        log.Fatalf("Failed to initialize backend: %v", err)
    }
    defer backend.Close()

    // Generate an RSA key
    rsaAttrs := &types.KeyAttributes{
        CN:           "my-rsa-key",
        KeyType:      types.KeyTypeTLS,
        StoreType:    types.StoreSoftware,
        KeyAlgorithm: x509.RSA,
        RSAAttributes: &types.RSAAttributes{
            KeySize: 2048,
        },
    }
    rsaKey, err := backend.GenerateKey(rsaAttrs)
    if err != nil {
        log.Fatalf("Failed to generate RSA key: %v", err)
    }
    fmt.Printf("RSA key generated: %T\n", rsaKey)

    // Generate an ECDSA key
    curve, _ := types.ParseCurve("P-256")
    ecdsaAttrs := &types.KeyAttributes{
        CN:           "my-ecdsa-key",
        KeyType:      types.KeyTypeSigning,
        StoreType:    types.StoreSoftware,
        KeyAlgorithm: x509.ECDSA,
        ECCAttributes: &types.ECCAttributes{
            Curve: curve,
        },
    }
    _, err = backend.GenerateKey(ecdsaAttrs)
    if err != nil {
        log.Fatalf("Failed to generate ECDSA key: %v", err)
    }
    fmt.Println("ECDSA key generated")

    // Generate an Ed25519 key
    edAttrs := &types.KeyAttributes{
        CN:           "my-ed25519-key",
        KeyType:      types.KeyTypeSigning,
        StoreType:    types.StoreSoftware,
        KeyAlgorithm: x509.Ed25519,
    }
    _, err = backend.GenerateKey(edAttrs)
    if err != nil {
        log.Fatalf("Failed to generate Ed25519 key: %v", err)
    }
    fmt.Println("Ed25519 key generated")

    // Sign data using the Signer interface
    signer, err := backend.Signer(rsaAttrs)
    if err != nil {
        log.Fatalf("Failed to get signer: %v", err)
    }
    digest := sha256.Sum256([]byte("Hello, World!"))
    signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
    if err != nil {
        log.Fatalf("Failed to sign: %v", err)
    }
    fmt.Printf("Signature: %d bytes\n", len(signature))

    // List all keys
    keys, err := backend.ListKeys()
    if err != nil {
        log.Fatalf("Failed to list keys: %v", err)
    }
    fmt.Printf("Total keys: %d\n", len(keys))
    for _, k := range keys {
        fmt.Printf("  - %s (%s)\n", k.CN, k.KeyAlgorithm)
    }

    // Rotate a key (deletes old, generates new)
    if err := backend.RotateKey(rsaAttrs); err != nil {
        log.Fatalf("Failed to rotate key: %v", err)
    }
    fmt.Println("RSA key rotated")

    // Delete a key
    if err := backend.DeleteKey(edAttrs); err != nil {
        log.Fatalf("Failed to delete key: %v", err)
    }
    fmt.Println("Ed25519 key deleted")

    _ = elliptic.P256() // suppress unused import if needed
}
```

## Password-Encrypted Keys

Private keys can be encrypted at rest by setting the `Password` field on `KeyAttributes`. The password is a `types.Password` interface.

```go
attrs := &types.KeyAttributes{
    CN:           "encrypted-key",
    KeyType:      types.KeyTypeTLS,
    StoreType:    types.StoreSoftware,
    KeyAlgorithm: x509.RSA,
    Password:     myPasswordImpl, // implements types.Password
    RSAAttributes: &types.RSAAttributes{
        KeySize: 4096,
    },
}

// GenerateKey stores the key encrypted via PKCS#8 EncryptedPrivateKeyInfo
key, err := backend.GenerateKey(attrs)

// GetKey decrypts it using the same password
key, err = backend.GetKey(attrs)
```

## Key Agreement (ECDH)

The backend implements `types.KeyAgreement` via `DeriveSharedSecret`. Supported curve families:

- **X25519** -- set `X25519Attributes` on `KeyAttributes`
- **NIST curves** (P-256, P-384, P-521) -- use ECDSA keys

```go
// Generate two X25519 keys
aliceAttrs := &types.KeyAttributes{
    CN:                "alice",
    KeyType:           types.KeyTypeEncryption,
    StoreType:         types.StoreSoftware,
    KeyAlgorithm:      x509.ECDSA, // algorithm field is ignored for X25519
    X25519Attributes:  &types.X25519Attributes{},
}
aliceKey, _ := backend.GenerateKey(aliceAttrs)

// Derive shared secret (requires casting to KeyAgreement)
ka := backend.(types.KeyAgreement)
secret, err := ka.DeriveSharedSecret(aliceAttrs, bobPublicKey)
```

## Error Types

All error sentinel values are defined in `pkg/keyprovider/pkcs8/errors.go`:

| Error                    | Description                                    |
|--------------------------|------------------------------------------------|
| `ErrKeyNotFound`         | Key does not exist in storage                  |
| `ErrKeyAlreadyExists`    | Key with this ID already exists                |
| `ErrInvalidKeyType`      | Unsupported key type                           |
| `ErrInvalidPassword`     | Password decryption failed                     |
| `ErrStorageClosed`       | Backend is closed                              |
| `ErrKeyEncodingFailed`   | PKCS#8 encoding failed                         |
| `ErrKeyDecodingFailed`   | PKCS#8 decoding failed                         |
| `ErrUnsupportedAlgorithm`| Unsupported algorithm                          |
| `ErrInvalidAttributes`   | Key attributes are invalid or incomplete       |
| `ErrKeyNotSigner`        | Key does not implement `crypto.Signer`         |
| `ErrKeyNotDecrypter`     | Key does not implement `crypto.Decrypter`      |

The backend also wraps errors from `pkg/backend` (e.g., `backend.ErrInvalidAttributes`, `backend.ErrKeyNotFound`, `backend.ErrKeyAlreadyExists`, `backend.ErrInvalidAlgorithm`, `backend.ErrInvalidKeyType`).

## Security Considerations

- Keys are software-based, not hardware-protected. Private keys exist in memory during operations.
- Password strength directly impacts at-rest encryption security. Use strong passwords from a secret manager.
- The `Close()` method marks the backend as closed; subsequent operations return `ErrStorageClosed`.
- Sealing derives AES-256-GCM keys from private key material via HKDF. This is not equivalent to hardware-bound sealing (TPM PCR binding).
- File system permissions on the underlying `storage.Backend` are the responsibility of the caller.

For applications requiring hardware-bound key protection, use the TPM2, PKCS#11, or cloud KMS backends instead.
