# Symmetric Encryption Guide

## Overview

The go-keychain library provides comprehensive symmetric encryption capabilities using AEAD (Authenticated Encryption with Associated Data) algorithms. This guide covers how to generate, store, and use symmetric keys across different backend providers.

**Supported Algorithms:**
- **AES-GCM** (128, 192, 256-bit) - Hardware-accelerated with AES-NI, FIPS compliant
- **ChaCha20-Poly1305** (256-bit) - Software-optimized, RFC 8439 compliant
- **XChaCha20-Poly1305** (256-bit, 192-bit nonce) - Extended nonce variant

**Key Features:**
- AEAD authenticated encryption with additional data
- Automatic algorithm selection based on hardware capabilities
- Multiple backend support (software, AWS KMS, GCP KMS, Azure Key Vault)
- Password-protected key storage with Argon2id
- Thread-safe operations
- Hardware-backed key storage (TPM2, PKCS#11)
- AEAD safety tracking (nonce reuse prevention, bytes limits)

## Supported Backends

The following backends support symmetric encryption operations:

| Backend | Description | Key Sizes | Hardware-Backed | Notes |
|---------|-------------|-----------|-----------------|-------|
| **AES** | AES-based encryption | 128, 192, 256 | No | Local key storage with optional password protection |
| **AWS KMS** | Amazon Key Management Service | 256 only | Yes | Keys never leave AWS infrastructure |
| **GCP KMS** | Google Cloud Key Management | 256 only | Yes | Keys never leave GCP infrastructure |
| **Azure Key Vault** | Microsoft Azure Key Vault | 128, 192, 256 | Yes | Uses envelope encryption (DEK wrapping) |
| **Vault** | HashiCorp Vault | 256 | Depends on backend | Transit secrets engine |
| **TPM2** | Trusted Platform Module 2.0 | 128, 256 | Yes | Hardware-bound keys |
| **PKCS#11** | Hardware Security Modules | 128, 192, 256 | Yes | HSM-backed operations |

**Note:** The PKCS#8 backend is designed for asymmetric key operations only and does not support symmetric encryption. Use the AES backend for local symmetric key storage.

## Quick Start

### 1. Symmetric Backend

The simplest way to get started with symmetric encryption using local key storage:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/symmetric"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func main() {
    // Create storage backends
    keyStorage := file.New("/var/lib/keys")
    certStorage := file.New("/var/lib/certs")

    // Create AES backend
    aesBackend := symmetric.NewBackend(keyStorage)

    // Create keystore
    keystore, err := keychain.New(&keychain.Config{
        Backend:     aesBackend,
        CertStorage: certStorage,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer keystore.Close()

    // Generate AES-256 key
    attrs := &backend.KeyAttributes{
        CN:           "my-encryption-key",
        KeyType:      backend.KEY_TYPE_SECRET,
        StoreType:    backend.STORE_SW,
        KeyAlgorithm: backend.ALG_AES256_GCM,
        AESAttributes: &backend.AESAttributes{
            KeySize: 256,
        },
    }

    symmetricKey, err := keystore.GenerateAES(attrs)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated AES key: %s (%d bits)\n",
        symmetricKey.Algorithm(), symmetricKey.KeySize())

    // Get encrypter for the key
    encrypter, err := keystore.SymmetricEncrypter(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data
    plaintext := []byte("Sensitive data to encrypt")
    encrypted, err := encrypter.Encrypt(plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Encrypted %d bytes\n", len(encrypted.Ciphertext))

    // Decrypt data
    decrypted, err := encrypter.Decrypt(encrypted, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

### 2. AWS KMS Backend

Use AWS Key Management Service for cloud-based key management:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func main() {
    // Create AWS KMS backend
    kmsBackend, err := awskms.NewBackend(&awskms.Config{
        Region: "us-west-2",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create certificate storage
    certStorage := file.New("/var/lib/certs")

    // Create keystore
    keystore, err := keychain.New(&keychain.Config{
        Backend:     kmsBackend,
        CertStorage: certStorage,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer keystore.Close()

    // Generate symmetric key in AWS KMS (256-bit only)
    attrs := &backend.KeyAttributes{
        CN:           "production-data-key",
        KeyType:      backend.KEY_TYPE_SECRET,
        StoreType:    backend.STORE_AWSKMS,
        KeyAlgorithm: backend.ALG_AES256_GCM,
        AESAttributes: &backend.AESAttributes{
            KeySize: 256, // AWS KMS only supports 256-bit keys
        },
    }

    symmetricKey, err := keystore.GenerateAES(attrs)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Created AWS KMS key: %s\n", symmetricKey.Algorithm())

    // Get encrypter
    encrypter, err := keystore.SymmetricEncrypter(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt data (AWS KMS handles nonce generation)
    plaintext := []byte("Database connection string: user:pass@host:port/db")
    encrypted, err := encrypter.Encrypt(plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Encrypted with AWS KMS\n")

    // Decrypt
    decrypted, err := encrypter.Decrypt(encrypted, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

### 3. GCP KMS Backend

Use Google Cloud Key Management Service:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/gcpkms"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func main() {
    // Create GCP KMS backend
    gcpBackend, err := gcpkms.NewBackend(&gcpkms.Config{
        ProjectID: "my-project",
        Location:  "us-central1",
        KeyRing:   "my-keyring",
    })
    if err != nil {
        log.Fatal(err)
    }

    certStorage := file.New("/var/lib/certs")

    keystore, err := keychain.New(&keychain.Config{
        Backend:     gcpBackend,
        CertStorage: certStorage,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer keystore.Close()

    // Generate symmetric key in GCP KMS
    attrs := &backend.KeyAttributes{
        CN:           "gcp-encryption-key",
        KeyType:      backend.KEY_TYPE_SECRET,
        StoreType:    backend.STORE_GCPKMS,
        KeyAlgorithm: backend.ALG_AES256_GCM,
        AESAttributes: &backend.AESAttributes{
            KeySize: 256,
        },
    }

    symmetricKey, err := keystore.GenerateAES(attrs)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Created GCP KMS key: %s\n", symmetricKey.Algorithm())

    // Use the key for encryption/decryption
    encrypter, err := keystore.SymmetricEncrypter(attrs)
    if err != nil {
        log.Fatal(err)
    }

    plaintext := []byte("Secret message")
    encrypted, err := encrypter.Encrypt(plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    decrypted, err := encrypter.Decrypt(encrypted, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Round-trip successful: %s\n", string(decrypted))
}
```

### 4. Azure Key Vault Backend

Use Microsoft Azure Key Vault:

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/backend/azurekv"
    "github.com/jeremyhahn/go-keychain/pkg/keychain"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

func main() {
    // Create Azure Key Vault backend
    azureBackend, err := azurekv.NewBackend(&azurekv.Config{
        VaultURL: "https://my-vault.vault.azure.net/",
    })
    if err != nil {
        log.Fatal(err)
    }

    certStorage := file.New("/var/lib/certs")

    keystore, err := keychain.New(&keychain.Config{
        Backend:     azureBackend,
        CertStorage: certStorage,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer keystore.Close()

    // Generate symmetric key in Azure Key Vault
    attrs := &backend.KeyAttributes{
        CN:           "azure-encryption-key",
        KeyType:      backend.KEY_TYPE_SECRET,
        StoreType:    backend.STORE_AZUREKV,
        KeyAlgorithm: backend.ALG_AES256_GCM,
        AESAttributes: &backend.AESAttributes{
            KeySize: 256,
        },
    }

    symmetricKey, err := keystore.GenerateAES(attrs)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Created Azure Key Vault key: %s\n", symmetricKey.Algorithm())

    // Encrypt and decrypt
    encrypter, err := keystore.SymmetricEncrypter(attrs)
    if err != nil {
        log.Fatal(err)
    }

    plaintext := []byte("Confidential information")
    encrypted, err := encrypter.Encrypt(plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    decrypted, err := encrypter.Decrypt(encrypted, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## Using Additional Authenticated Data (AAD)

AAD allows you to bind ciphertext to a specific context without encrypting the context data:

```go
// Encrypt with AAD
opts := &backend.EncryptOptions{
    AdditionalData: []byte("user-id:12345,timestamp:2025-11-07"),
}

encrypted, err := encrypter.Encrypt(plaintext, opts)
if err != nil {
    log.Fatal(err)
}

// Decrypt with same AAD (required for authentication)
decryptOpts := &backend.DecryptOptions{
    AdditionalData: []byte("user-id:12345,timestamp:2025-11-07"),
}

decrypted, err := encrypter.Decrypt(encrypted, decryptOpts)
if err != nil {
    log.Fatal(err) // Will fail if AAD doesn't match
}
```

**Use Cases for AAD:**
- Binding encrypted data to user IDs
- Including version information
- Adding timestamps
- Associating with database record IDs
- Including file paths or names

## Password-Protected Keys

Protect locally stored keys with a password (AES backend only):

```go
// Create password
password := backend.StaticPassword([]byte("my-secret-password"))

// Generate password-protected key
attrs := &backend.KeyAttributes{
    CN:           "protected-key",
    KeyType:      backend.KEY_TYPE_SECRET,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_AES256_GCM,
    Password:     password,
    AESAttributes: &backend.AESAttributes{
        KeySize: 256,
    },
}

symmetricKey, err := keystore.GenerateAES(attrs)
if err != nil {
    log.Fatal(err)
}

fmt.Println("Generated password-protected key")

// Later retrieval requires the same password
retrievedKey, err := keystore.GetSymmetricKey(attrs)
if err != nil {
    log.Fatal("Failed to retrieve key - wrong password?")
}

fmt.Printf("Retrieved key: %s\n", retrievedKey.Algorithm())
```

**Password Security:**
- Uses Argon2id for key derivation (memory-hard, resistant to GPU attacks)
- Parameters: time=1, memory=64MB, threads=4
- 32-byte random salt per key
- AES-256-GCM encryption of key material

## Checking Backend Support

Verify if a backend supports symmetric encryption:

```go
// Method 1: Type assertion
if symBackend, ok := backend.(backend.SymmetricBackend); ok {
    // Backend supports symmetric operations
    key, err := symBackend.GenerateSymmetricKey(attrs)
} else {
    log.Fatal("Backend does not support symmetric encryption")
}

// Method 2: Capabilities check
caps := backend.Capabilities()
if caps.SupportsSymmetricEncryption() {
    fmt.Println("Symmetric encryption is supported")
} else {
    fmt.Println("Symmetric encryption is NOT supported")
}
```

## API Reference

### Key Types and Algorithms

```go
// Symmetric algorithms (AEAD)
const (
    // AES-GCM algorithms
    SymmetricAES128GCM SymmetricAlgorithm = "aes128-gcm" // 128-bit AES-GCM
    SymmetricAES192GCM SymmetricAlgorithm = "aes192-gcm" // 192-bit AES-GCM
    SymmetricAES256GCM SymmetricAlgorithm = "aes256-gcm" // 256-bit AES-GCM (recommended)

    // ChaCha20-Poly1305 algorithms (RFC 8439)
    SymmetricChaCha20Poly1305  SymmetricAlgorithm = "chacha20-poly1305"  // 256-bit, 96-bit nonce
    SymmetricXChaCha20Poly1305 SymmetricAlgorithm = "xchacha20-poly1305" // 256-bit, 192-bit nonce
)

// Key type for symmetric keys
KeyTypeSecret KeyType = "secret"
```

**Algorithm Comparison:**

| Algorithm | Key Size | Nonce Size | Best For |
|-----------|----------|------------|----------|
| `aes128-gcm` | 128-bit | 96-bit | General purpose |
| `aes192-gcm` | 192-bit | 96-bit | Extended security |
| `aes256-gcm` | 256-bit | 96-bit | Maximum security, FIPS compliance |
| `chacha20-poly1305` | 256-bit | 96-bit | Software-only (no AES-NI) |
| `xchacha20-poly1305` | 256-bit | 192-bit | Safe random nonce generation |

### Core Interfaces

#### SymmetricKey

Represents a symmetric encryption key:

```go
type SymmetricKey interface {
    Algorithm() string  // Returns algorithm identifier (e.g., "aes256-gcm")
    KeySize() int       // Returns key size in bits (128, 192, or 256)
    Raw() []byte        // Returns raw key bytes (use with caution)
}
```

#### SymmetricEncrypter

Provides encryption and decryption operations:

```go
type SymmetricEncrypter interface {
    // Encrypt encrypts plaintext with optional additional authenticated data
    Encrypt(plaintext []byte, opts *EncryptOptions) (*EncryptedData, error)

    // Decrypt decrypts ciphertext, verifying authentication
    Decrypt(data *EncryptedData, opts *DecryptOptions) ([]byte, error)
}
```

#### EncryptOptions

Options for encryption operations:

```go
type EncryptOptions struct {
    // AdditionalData is authenticated but not encrypted (AEAD)
    AdditionalData []byte

    // Nonce is the nonce/IV to use. If nil, a random nonce is generated.
    // For GCM, this should be 12 bytes (96 bits).
    Nonce []byte
}
```

#### DecryptOptions

Options for decryption operations:

```go
type DecryptOptions struct {
    // AdditionalData must match what was used during encryption
    AdditionalData []byte
}
```

#### EncryptedData

Result of an encryption operation:

```go
type EncryptedData struct {
    Ciphertext []byte  // Encrypted data
    Nonce      []byte  // Nonce/IV (12 bytes for GCM)
    Tag        []byte  // Authentication tag (16 bytes for GCM)
    Algorithm  string  // Algorithm identifier
}
```

### KeyStore Methods

High-level keystore interface:

```go
// Generate a new AES key
GenerateAES(attrs *KeyAttributes) (SymmetricKey, error)

// Retrieve an existing symmetric key
GetSymmetricKey(attrs *KeyAttributes) (SymmetricKey, error)

// Get an encrypter for a key
SymmetricEncrypter(attrs *KeyAttributes) (SymmetricEncrypter, error)
```

### Backend Methods

Backend interface for symmetric operations:

```go
type SymmetricBackend interface {
    Backend // Extends base Backend interface

    // Generate a new symmetric key
    GenerateSymmetricKey(attrs *KeyAttributes) (SymmetricKey, error)

    // Retrieve an existing symmetric key
    GetSymmetricKey(attrs *KeyAttributes) (SymmetricKey, error)

    // Get an encrypter for a key
    SymmetricEncrypter(attrs *KeyAttributes) (SymmetricEncrypter, error)
}
```

## Security Considerations

### Nonce Management

**Critical:** Never reuse a nonce with the same key!

- Each encryption operation generates a unique random nonce (12 bytes)
- Store the nonce with the ciphertext (included in `EncryptedData`)
- Use `crypto/rand` for nonce generation (never use `math/rand`)
- For high-throughput scenarios, consider counter-based nonces with proper synchronization

### Authentication Tag Verification

- AES-GCM provides authenticated encryption (AEAD)
- The 16-byte tag verifies both ciphertext and AAD integrity
- Decryption automatically fails if the tag is invalid
- This protects against tampering and bit-flipping attacks

### Key Storage Security

**AES Keys:**
- Store keys with restricted file permissions (0600)
- Use password protection for sensitive keys
- Consider OS keyring integration for password storage
- Regularly rotate keys

**Cloud KMS Keys:**
- Key material never leaves the KMS infrastructure
- Use IAM/RBAC for access control
- Enable audit logging (CloudTrail, Cloud Logging, etc.)
- Implement key rotation policies
- Use envelope encryption for large data

**Hardware Keys (HSM/TPM):**
- Keys are hardware-bound and non-exportable
- Use hardware authentication mechanisms
- Consider attestation for key verification

### Best Practices

1. **Use 256-bit keys** for maximum security
2. **Enable AAD** to bind ciphertext to context
3. **Store nonces** with ciphertext (required for decryption)
4. **Implement key rotation** (e.g., every 90 days)
5. **Use hardware backing** (KMS, HSM, TPM) for production systems
6. **Monitor key usage** via audit logs
7. **Never log plaintext** or key material
8. **Use envelope encryption** for large datasets
9. **Verify backend capabilities** before use
10. **Handle errors properly** (authentication failures may indicate attacks)

### Threat Model

**Protections Provided:**
- Confidentiality (encryption at rest and in transit)
- Integrity (authentication via GCM)
- Context binding (via AAD)
- Hardware backing (KMS, HSM, TPM)

**Limitations:**
- Not protected against memory attacks (keys in process memory)
- Side-channel attacks (timing, cache) require additional mitigations
- Insider threats require access control policies
- Not quantum-resistant (use post-quantum algorithms when available)

## Migration Guide

### Adding Symmetric Encryption to Existing Applications

If you're already using go-keychain for asymmetric operations, adding symmetric encryption is straightforward:

#### Step 1: Check Backend Support

```go
// Check if your backend supports symmetric encryption
caps := backend.Capabilities()
if !caps.SupportsSymmetricEncryption() {
    // Consider switching backends or adding a secondary backend
    log.Warn("Current backend doesn't support symmetric encryption")
}
```

#### Step 2: Generate Symmetric Keys

```go
// Add symmetric key generation alongside existing asymmetric keys
attrs := &backend.KeyAttributes{
    CN:           "data-encryption-key",
    KeyType:      backend.KEY_TYPE_SECRET,
    StoreType:    backend.STORE_SW, // or your backend type
    KeyAlgorithm: backend.ALG_AES256_GCM,
    AESAttributes: &backend.AESAttributes{
        KeySize: 256,
    },
}

symmetricKey, err := keystore.GenerateAES(attrs)
if err != nil {
    log.Fatal(err)
}
```

#### Step 3: Encrypt/Decrypt Data

```go
// Replace existing encryption code with symmetric operations
encrypter, err := keystore.SymmetricEncrypter(attrs)
if err != nil {
    log.Fatal(err)
}

// Encrypt
encrypted, err := encrypter.Encrypt(plaintext, &backend.EncryptOptions{
    AdditionalData: []byte("context-info"),
})

// Decrypt
decrypted, err := encrypter.Decrypt(encrypted, &backend.DecryptOptions{
    AdditionalData: []byte("context-info"),
})
```

#### Step 4: Serialize Encrypted Data

```go
// Use the provided serialization helpers
import "github.com/jeremyhahn/go-keychain/pkg/backend/symmetric"

// Serialize for storage/transmission
serialized, err := symmetric.Marshal(encrypted)
if err != nil {
    log.Fatal(err)
}

// Store serialized data
err = storage.Save("encrypted-data.bin", serialized)

// Later: deserialize
data, err := storage.Load("encrypted-data.bin")
encrypted, err := symmetric.Unmarshal(data)
```

### Hybrid Asymmetric/Symmetric Usage

Combine asymmetric and symmetric encryption for optimal performance:

```go
// Use asymmetric encryption for key exchange
asymmetricKey, _ := keystore.GenerateRSA(rsaAttrs)

// Use symmetric encryption for data
symmetricKey, _ := keystore.GenerateAES(aesAttrs)

// Encrypt large data with symmetric key
dataEncrypter, _ := keystore.SymmetricEncrypter(aesAttrs)
encryptedData, _ := dataEncrypter.Encrypt(largeData, nil)

// Encrypt symmetric key with asymmetric key
keyEncrypter, _ := keystore.Decrypter(rsaAttrs)
// ... (use asymmetric encryption for key wrapping)
```

## Performance Considerations

### Throughput Benchmarks

Approximate performance on modern hardware (Intel Xeon, AES-NI enabled):

| Backend | Operation | Throughput |
|---------|-----------|------------|
| AES | Encrypt | 500-1000 MB/s |
| AES | Decrypt | 500-1000 MB/s |
| AWS KMS | Encrypt/Decrypt | 100-500 ops/s |
| GCP KMS | Encrypt/Decrypt | 100-500 ops/s |
| Azure Key Vault | Encrypt/Decrypt | 100-500 ops/s |
| TPM2 | Encrypt/Decrypt | 1-10 MB/s |
| PKCS#11 (HSM) | Encrypt/Decrypt | 10-100 MB/s |

### Optimization Tips

1. **Use local encryption for large data** with KMS-based envelope encryption
2. **Batch operations** when possible to reduce round-trips
3. **Consider caching** encrypters (they're reusable)
4. **Pre-generate keys** during initialization rather than on-demand
5. **Use hardware acceleration** (AES-NI) when available

## Troubleshooting

### Common Errors

**"Backend does not support symmetric encryption"**
- Check backend capabilities before use
- Consider using AES backend for local symmetric key storage
- Note: PKCS#8 backend is for asymmetric keys only

**"Authentication error" during decryption**
- Verify AAD matches between encryption and decryption
- Check that nonce and tag are correctly stored and retrieved
- Data may have been tampered with

**"Invalid AES key size"**
- AWS KMS and GCP KMS only support 256-bit keys
- Verify `KeySize` in `AESAttributes` is 128, 192, or 256

**"Failed to retrieve key - wrong password"**
- Ensure the same password is used for generation and retrieval
- Password is stored with the key attributes

### Debug Logging

Enable debug logging to troubleshoot issues:

```go
import "log"

// Set up debug logging
log.SetFlags(log.LstdFlags | log.Lshortfile)

// Wrap operations with logging
log.Printf("Generating key with attributes: %+v", attrs)
key, err := keystore.GenerateAES(attrs)
if err != nil {
    log.Printf("Key generation failed: %v", err)
}
```

## Additional Resources

- [Design Document](design/symmetric-encryption.md) - Detailed architecture and implementation
- [Backend Documentation](backends/) - Backend-specific details
- [API Specifications](architecture/API_SPECIFICATIONS.md) - Complete API reference
- [Examples](../examples/) - Working code examples

## Support

For questions, issues, or contributions:
- GitHub Issues: [github.com/jeremyhahn/go-keychain/issues](https://github.com/jeremyhahn/go-keychain/issues)
- Documentation: [docs/](.)
