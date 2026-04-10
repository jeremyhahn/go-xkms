# Quantum Backend Documentation

## Overview

The quantum backend provides post-quantum cryptographic operations using NIST-standardized algorithms. This implementation uses ML-DSA (Module-Lattice Digital Signature Algorithm, FIPS 204) for signing via Cloudflare's `circl` library and ML-KEM (Module-Lattice Key Encapsulation Mechanism, FIPS 203) for key establishment via Go's standard library `crypto/mlkem` package.

Both implementations are pure Go -- no CGO, no external C libraries, and no special build tags are required. Quantum support is always compiled in.

Post-quantum cryptography protects against attacks from both classical and quantum computers. The quantum backend implements NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards, providing quantum-resistant security for long-term data protection and future-proof cryptographic operations.

## Service Integration

Quantum support is always available -- no build tags or external dependencies are required. The backend auto-registers with the xkms service registry.

### Checking Availability

```go
import "github.com/jeremyhahn/go-xkms/pkg/xkms"

if xkms.IsBackendSupported(xkms.BackendQuantum) {
    fmt.Println("Quantum backend is available")
}
```

### Using via Service API

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Generate a post-quantum signing key
key, err := xkms.GenerateKeyWithBackend("quantum", &types.KeyAttributes{
    CN:        "pq-signing-key",
    KeyType:   types.KeyTypeSigning,
    StoreType: types.StoreQuantum,
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLDSA65,
    },
})

// Sign using the key ID with explicit backend
sig, err := xkms.Sign("quantum:::pq-signing-key", data, nil)
```

### Auto-Initialize

```go
err := xkms.AutoInitialize(&xkms.AutoConfig{
    DataDir: "/var/lib/xkms",
    BackendConfigs: map[xkms.BackendType]map[string]interface{}{
        xkms.BackendQuantum: {
            "key_dir": "/var/lib/xkms/quantum/keys",
        },
    },
})
defer xkms.Close()
```

## Supported Algorithms

### ML-DSA (Digital Signatures)

Module-Lattice Digital Signature Algorithm, standardized as NIST FIPS 204. Implemented via Cloudflare's `circl` library (`github.com/cloudflare/circl/sign/mldsa`).

- ML-DSA-44: NIST Security Level 2 (equivalent to AES-128)
  - Public key: 1312 bytes
  - Signature: 2420 bytes

- ML-DSA-65: NIST Security Level 3 (equivalent to AES-192) **recommended**
  - Public key: 1952 bytes
  - Signature: 3309 bytes

- ML-DSA-87: NIST Security Level 5 (equivalent to AES-256)
  - Public key: 2592 bytes
  - Signature: 4627 bytes

### ML-KEM (Key Encapsulation)

Module-Lattice Key Encapsulation Mechanism, standardized as NIST FIPS 203. Implemented via Go's standard library `crypto/mlkem` package.

- ML-KEM-768: NIST Security Level 3 (equivalent to AES-192) **recommended**
  - Public key: 1184 bytes
  - Ciphertext: 1088 bytes
  - Shared secret: 32 bytes

- ML-KEM-1024: NIST Security Level 5 (equivalent to AES-256)
  - Public key: 1568 bytes
  - Ciphertext: 1568 bytes
  - Shared secret: 32 bytes

**Note**: ML-KEM is not direct encryption. It establishes a shared secret that is used with AES-256-GCM for actual data encryption.

## Configuration

### Basic Configuration

```go
type Config struct {
    Tracker types.AEADSafetyTracker  // Optional AEAD safety tracker
}
```

### Simple Setup

```go
import (
    "github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
    "github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Initialize storage
store, err := storage.NewMemoryBackend()
if err != nil {
    log.Fatalf("Failed to create storage: %v", err)
}

// Create quantum backend with defaults
backend, err := quantum.New(store)
if err != nil {
    log.Fatalf("Failed to create quantum backend: %v", err)
}
defer backend.Close()
```

### With Custom AEAD Tracker

```go
import "github.com/jeremyhahn/go-xkms/pkg/backend"

// Create custom tracker for AEAD safety
tracker := backend.NewMemoryAEADTracker()

config := &quantum.Config{
    Tracker: tracker,
}

backend, err := quantum.NewWithConfig(store, config)
```

## Usage Examples

### Generating ML-DSA Signing Keys

```go
import "github.com/jeremyhahn/go-xkms/pkg/types"

// Generate ML-DSA-65 key (NIST Level 3)
attrs := &types.KeyAttributes{
    CN:        "signing-key",
    KeyType:   types.KeyTypeSigning,
    StoreType: types.StoreQuantum,
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLDSA65,
    },
}

privKey, err := backend.GenerateKey(attrs)
if err != nil {
    log.Fatalf("Failed to generate key: %v", err)
}
```

### Signing and Verification

```go
import (
    "crypto"
    "crypto/rand"
    "crypto/sha256"
)

// Get signer (implements crypto.Signer interface)
signer, err := backend.Signer(attrs)
if err != nil {
    log.Fatalf("Failed to get signer: %v", err)
}

// Sign data
message := []byte("Message to sign")
hash := sha256.Sum256(message)

signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
if err != nil {
    log.Fatalf("Failed to sign: %v", err)
}

// Verify signature
mldsaKey := privKey.(*quantum.MLDSAPrivateKey)
valid, err := mldsaKey.Verify(message, signature)
if err != nil {
    log.Fatalf("Verification error: %v", err)
}

if !valid {
    log.Fatal("Signature verification failed")
}
```

### Generating ML-KEM Encryption Keys

```go
// Generate ML-KEM-768 key (NIST Level 3)
kemAttrs := &types.KeyAttributes{
    CN:        "encryption-key",
    KeyType:   types.KeyTypeEncryption,
    StoreType: types.StoreQuantum,
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLKEM768,
    },
}

privKey, err := backend.GenerateKey(kemAttrs)
if err != nil {
    log.Fatalf("Failed to generate key: %v", err)
}
```

### Quantum-Safe Encryption

ML-KEM provides key encapsulation, not direct encryption. The backend implements convenient Encrypt/Decrypt methods that combine ML-KEM with AES-256-GCM:

```go
mlkemKey := privKey.(*quantum.MLKEMPrivateKey)
publicKey := mlkemKey.PublicKey.Bytes()

// Encrypt
plaintext := []byte("Secret message")
kemCiphertext, encryptedData, err := mlkemKey.Encrypt(plaintext, publicKey)
if err != nil {
    log.Fatalf("Encryption failed: %v", err)
}

// Send both kemCiphertext and encryptedData to recipient

// Decrypt
decrypted, err := mlkemKey.Decrypt(kemCiphertext, encryptedData)
if err != nil {
    log.Fatalf("Decryption failed: %v", err)
}
```

**How it works:**
1. ML-KEM encapsulates a random 32-byte shared secret to recipient's public key
2. Shared secret is used as AES-256-GCM key to encrypt plaintext
3. Returns both KEM ciphertext (1088 bytes for ML-KEM-768) and encrypted data
4. Recipient decapsulates KEM ciphertext to recover shared secret
5. Shared secret decrypts the data with AES-256-GCM

### Encryption with Additional Authenticated Data

```go
plaintext := []byte("Transfer $1,000 to account 12345")
aad := []byte("user-id:alice|timestamp:2025-01-15")

// Encrypt with AAD
kemCt, encData, err := mlkemKey.EncryptWithAAD(plaintext, aad, publicKey)
if err != nil {
    log.Fatalf("Encryption failed: %v", err)
}

// Decrypt with AAD verification
decrypted, err := mlkemKey.DecryptWithAAD(kemCt, encData, aad)
if err != nil {
    log.Fatal("Decryption failed - AAD mismatch or tampering")
}
```

### Key Rotation

```go
// Generate initial key
attrs := &types.KeyAttributes{
    CN:        "rotatable-key",
    KeyType:   types.KeyTypeEncryption,
    StoreType: types.StoreQuantum,
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLKEM768,
    },
}

privKey, err := backend.GenerateKey(attrs)

// Later: rotate to new key
err = backend.RotateKey(attrs)
if err != nil {
    log.Fatalf("Key rotation failed: %v", err)
}

// Get the new key
newPrivKey, err := backend.GetKey(attrs)
```

**Note**: Key rotation automatically resets AEAD tracking (nonce history and bytes counter) for ML-KEM keys.

## AEAD Safety Tracking

ML-KEM encryption uses AES-256-GCM internally, which requires strict nonce management and usage limits per NIST SP 800-38D. The quantum backend integrates with go-xkms's AEAD safety tracking to enforce these requirements.

### Default Protection

AEAD tracking is enabled by default with recommended settings:

- Nonce uniqueness checking (prevents catastrophic nonce reuse)
- Bytes encrypted tracking (enforces 350GB limit per key)
- Automatic tracking on all ML-KEM encrypt operations
- Tracking reset on key rotation

### Monitoring Usage

```go
keyID := attrs.ID()

// Get bytes encrypted with this key
bytesEncrypted, err := tracker.GetBytesEncrypted(keyID)
if err != nil {
    log.Printf("Failed to get bytes: %v", err)
}

// Get AEAD options
opts, err := tracker.GetAEADOptions(keyID)
if err != nil {
    log.Printf("Failed to get options: %v", err)
}

// Calculate usage
percentUsed := float64(bytesEncrypted) / float64(opts.BytesTrackingLimit) * 100
if percentUsed >= 90.0 {
    log.Printf("WARNING: Key usage at %.1f%% - rotation recommended", percentUsed)
}
```

### Custom Limits

```go
keyID := attrs.ID()

// Set custom 100GB limit
customOpts := &types.AEADOptions{
    NonceTracking:      true,
    BytesTracking:      true,
    BytesTrackingLimit: 100 * 1024 * 1024 * 1024,
    NonceSize:          12,
}

err := tracker.SetAEADOptions(keyID, customOpts)
if err != nil {
    log.Printf("Failed to set options: %v", err)
}
```

### Handling Limits

```go
kemCt, encData, err := mlkemKey.Encrypt(plaintext, publicKey)
if err != nil {
    if strings.Contains(err.Error(), "bytes limit exceeded") {
        log.Println("Key rotation required - bytes limit reached")

        // Rotate key
        err = backend.RotateKey(attrs)
        if err != nil {
            log.Fatalf("Rotation failed: %v", err)
        }

        // Retry with new key
        newPrivKey, _ := backend.GetKey(attrs)
        newMLKemKey := newPrivKey.(*quantum.MLKEMPrivateKey)
        kemCt, encData, err = newMLKemKey.Encrypt(plaintext, publicKey)
    }
}
```

## Performance Characteristics

Typical performance on modern hardware:

### ML-DSA-65
- Key generation: ~90 microseconds
- Signing: ~180 microseconds
- Verification: ~45 microseconds

### ML-KEM-768
- Key generation: ~33 microseconds
- Encapsulation: ~18 microseconds
- Decapsulation: ~16 microseconds

### Encryption Overhead
- ML-KEM overhead: ~1088 bytes (fixed)
- AES-GCM overhead: ~28 bytes
- Total overhead: ~1116 bytes (0.11% for 1MB data)

AEAD tracking adds <3 microseconds per encryption operation.

## Size Comparison

Quantum algorithms use larger keys and signatures compared to classical algorithms:

| Operation | Classical (ECDSA P-256) | Quantum (ML-DSA-65) | Increase |
|-----------|-------------------------|---------------------|----------|
| Public key | 65 bytes | 1952 bytes | 30x |
| Signature | 71 bytes | 3309 bytes | 47x |

| Operation | Classical (ECDH P-256) | Quantum (ML-KEM-768) | Increase |
|-----------|------------------------|----------------------|----------|
| Public key | 65 bytes | 1184 bytes | 18x |
| Ciphertext | N/A | 1088 bytes | N/A |

The size increase is the trade-off for quantum resistance. For most applications, the additional bandwidth is acceptable given the long-term security benefits.

## Build Requirements

Quantum support is built in by default with no special build tags or external dependencies:

```bash
# Build (quantum support included automatically)
go build ./...

# Run tests
go test ./pkg/keyprovider/quantum/

# Docker integration tests
make integration-test-quantum
```

### Dependencies

All quantum cryptographic dependencies are pure Go:

- **ML-DSA**: `github.com/cloudflare/circl/sign/mldsa/{mldsa44,mldsa65,mldsa87}`
- **ML-KEM**: Go standard library `crypto/mlkem` (ML-KEM-768, ML-KEM-1024)

No CGO, cmake, ninja, pkg-config, or external C libraries are required.

## Integration with Other Backends

The quantum backend implements the same `Backend` interface as all other backends (Software, TPM2, PKCS11, etc.), enabling:

- Seamless integration with backend registry
- Same API for key generation, signing, encryption
- Compatible with existing KeyStore implementations
- Works with gRPC, REST, and CLI services

```go
// Register quantum alongside other backends
registry.Register("software", softwareBackend)
registry.Register("tpm2", tpm2Backend)
registry.Register("quantum", quantumBackend)

// Use same API for all backends
backend := registry.GetBackend("quantum")
privKey, _ := backend.GenerateKey(attrs)
signer, _ := backend.Signer(attrs)
```

## Security Considerations

### Quantum Resistance

ML-DSA and ML-KEM are designed to resist attacks from both classical and quantum computers. These algorithms are based on the hardness of lattice problems, which are believed to be intractable even for quantum computers.

### NIST Standardization

Both algorithms are NIST-standardized:
- ML-KEM: FIPS 203 (published August 2024)
- ML-DSA: FIPS 204 (published August 2024)

### Hybrid Approaches

For maximum security during the transition period, consider using both classical and quantum algorithms:

```go
// Classical ECDSA signature
ecdsaSigner, _ := softwareBackend.Signer(ecdsaAttrs)
ecdsaSig, _ := ecdsaSigner.Sign(rand.Reader, hash[:], crypto.SHA256)

// Quantum ML-DSA signature
mldsaSigner, _ := quantumBackend.Signer(mldsaAttrs)
mldsaSig, _ := mldsaSigner.Sign(rand.Reader, hash[:], crypto.SHA256)

// Send both signatures - provides defense in depth
```

### Long-Term Protection

Use quantum cryptography when:
- Data must remain secure for decades
- Protecting against "harvest now, decrypt later" attacks
- Compliance requires post-quantum cryptography
- Future-proofing cryptographic infrastructure

## Limitations

### Not Supported

- Hardware-backed keys (no HSM/TPM integration)
- Quantum algorithms in X.509 certificates (limited PKI support)
- Streaming encryption (use block-based approach)
- ML-KEM-512 (not available in Go standard library)

### Platform Constraints

- Pure Go implementation -- runs on all platforms supported by Go
- No CGO or external C library dependencies

### Network Overhead

Larger keys and signatures increase bandwidth requirements:
- ML-DSA-65 signatures: ~3.3KB each
- ML-KEM-768 ciphertexts: ~1.1KB each

Plan accordingly for constrained networks or high-volume applications.

## Troubleshooting

### AEAD limit exceeded

```
bytes limit exceeded (key rotation required)
```

Solution: Rotate the key:
```go
backend.RotateKey(attrs)
```

## See Also

- [Post-Quantum Cryptography Architecture](../architecture/post-quantum-cryptography.md)
- [AEAD Bytes Tracking](../configuration/aead-bytes-tracking.md)
- [Backend Registry](../architecture/backend-registry.md)
- [Integration Tests](../testing/integration-tests.md)
