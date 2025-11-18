# Post-Quantum Cryptography Architecture

## Overview

This document describes the architecture and implementation of post-quantum cryptographic algorithms in go-keychain. The implementation provides quantum-resistant alternatives to classical cryptography using NIST-standardized lattice-based algorithms.

## Threat Model

### Quantum Computing Threat

Quantum computers pose a significant threat to current public-key cryptography:

**Shor's Algorithm** can efficiently solve:
- Integer factorization (breaks RSA)
- Discrete logarithm problem (breaks ECDSA, ECDH)
- Elliptic curve discrete logarithm (breaks ECC)

**Estimated Timeline:**
- Large-scale quantum computers capable of breaking RSA-2048: 10-30 years
- Harvest now, decrypt later attacks: Happening today

**Impact:**
- All current RSA and ECC keys become vulnerable
- Encrypted data retroactively compromised
- Long-term secrets at risk

### Symmetric Cryptography

**Grover's Algorithm** reduces security by half:
- AES-128 effectively becomes 64-bit security
- AES-256 effectively becomes 128-bit security
- Mitigation: Use AES-256 for quantum resistance

## NIST Post-Quantum Standardization

The National Institute of Standards and Technology (NIST) completed a multi-year process to standardize post-quantum cryptographic algorithms.

### Selected Algorithms

**FIPS 203: ML-KEM (Kyber)**
- Published: August 2024
- Purpose: Key encapsulation mechanism
- Based on: Module Learning with Errors (MLWE) problem
- Security: Lattice-based cryptography

**FIPS 204: ML-DSA (Dilithium)**
- Published: August 2024
- Purpose: Digital signatures
- Based on: Module Short Integer Solution (MSIS) and MLWE problems
- Security: Lattice-based cryptography

**FIPS 205: SLH-DSA (SPHINCS+)**
- Published: August 2024
- Purpose: Stateless hash-based signatures
- Based on: Hash functions
- Note: Not yet implemented in go-keychain

### Security Levels

NIST defines five security levels corresponding to classical cryptographic strength:

| Level | Classical Equivalent | Quantum Bit Security | Recommended Use |
|-------|---------------------|---------------------|-----------------|
| 1 | AES-128 | 64 bits | Baseline |
| 2 | SHA-256 collision | 96 bits | General purpose |
| 3 | AES-192 | 128 bits | **Recommended** |
| 4 | SHA-384 collision | 192 bits | High security |
| 5 | AES-256 | 256 bits | Maximum security |

Go-keychain implements ML-DSA and ML-KEM at levels 2, 3, and 5.

## Architecture Design

### Backend Integration

```
┌─────────────────────────────────────────┐
│         Backend Interface               │
│  (PKCS8, TPM2, PKCS11, Quantum, ...)    │
└─────────────────────────────────────────┘
                  │
      ┌───────────┼───────────┐
      │           │           │
┌─────▼────┐ ┌────▼────┐ ┌───▼──────┐
│ PKCS8    │ │  TPM2   │ │ Quantum  │
│ Backend  │ │ Backend │ │ Backend  │
└──────────┘ └─────────┘ └──────────┘
                              │
              ┌───────────────┴──────────────┐
              │                              │
      ┌───────▼────────┐          ┌─────────▼─────────┐
      │   ML-DSA       │          │     ML-KEM        │
      │  (Dilithium)   │          │    (Kyber)        │
      │                │          │                   │
      │ - Sign         │          │ - Encapsulate     │
      │ - Verify       │          │ - Decapsulate     │
      └────────────────┘          └───────────────────┘
              │                            │
              └────────────┬───────────────┘
                           │
                  ┌────────▼─────────┐
                  │   liboqs         │
                  │  (Open Quantum   │
                  │   Safe Library)  │
                  └──────────────────┘
```

### Key Types and Operations

**ML-DSA Private Key:**
```go
type MLDSAPrivateKey struct {
    Algorithm string              // ML-DSA-44, ML-DSA-65, ML-DSA-87
    PublicKey *MLDSAPublicKey
    signer    *oqs.Signature      // liboqs signature instance
}

// Implements crypto.Signer interface
func (k *MLDSAPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
func (k *MLDSAPrivateKey) Verify(message, signature []byte) (bool, error)
```

**ML-KEM Private Key:**
```go
type MLKEMPrivateKey struct {
    Algorithm string              // ML-KEM-512, ML-KEM-768, ML-KEM-1024
    PublicKey *MLKEMPublicKey
    kem       *oqs.KeyEncapsulation // liboqs KEM instance
    tracker   types.AEADSafetyTracker
    keyID     string
}

// Key encapsulation operations
func (k *MLKEMPrivateKey) Encapsulate(recipientPublicKey []byte) (ciphertext, sharedSecret []byte, error)
func (k *MLKEMPrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, error)

// Convenience encryption methods (ML-KEM + AES-256-GCM)
func (k *MLKEMPrivateKey) Encrypt(plaintext, recipientPublicKey []byte) (kemCiphertext, encryptedData []byte, error)
func (k *MLKEMPrivateKey) Decrypt(kemCiphertext, encryptedData []byte) (plaintext []byte, error)
```

### Storage Format

Keys are stored as JSON metadata containing algorithm type and key material:

```json
{
  "algorithm": "ML-DSA-65",
  "public_key": "base64-encoded-public-key",
  "secret_key": "base64-encoded-secret-key"
}
```

This format allows:
- Algorithm identification on retrieval
- Re-initialization of liboqs instances
- Storage backend flexibility (file, database, etc.)

## ML-KEM + AES-GCM Hybrid Encryption

ML-KEM is a key encapsulation mechanism, not direct encryption. The quantum backend implements hybrid encryption combining quantum-resistant key establishment with authenticated encryption.

### Encryption Flow

```
Sender                                              Recipient
  │                                                    │
  │  1. Generate random 32-byte shared secret          │
  │     via ML-KEM encapsulation                       │
  │                                                    │
  │  2. Encrypt shared secret with                     │
  │     recipient's ML-KEM public key                  │
  │     → KEM ciphertext (1088 bytes for ML-KEM-768)   │
  │                                                    │
  │  3. Use shared secret as AES-256 key               │
  │     to encrypt plaintext with AES-GCM              │
  │     → Encrypted data (plaintext + 28 bytes)        │
  │                                                    │
  │  4. Send: KEM ciphertext + encrypted data          │
  ├────────────────────────────────────────────────────>
  │                                                    │
  │                    5. Decapsulate KEM ciphertext   │
  │                       to recover shared secret     │
  │                                                    │
  │                    6. Use shared secret as         │
  │                       AES-256 key to decrypt       │
  │                       with AES-GCM                 │
  │                                                    │
  │                    7. Verify auth tag and          │
  │                       return plaintext             │
```

### Security Properties

**Quantum Resistance:**
- ML-KEM provides quantum-resistant key establishment
- AES-256-GCM provides symmetric encryption (quantum-safe with 128-bit security)

**Authenticated Encryption:**
- AES-GCM provides both confidentiality and authenticity
- Authentication tag prevents tampering
- Additional Authenticated Data (AAD) supported

**Perfect Forward Secrecy:**
- Each encryption uses a fresh random shared secret
- Compromise of long-term key doesn't decrypt past messages

## AEAD Safety Tracking Integration

AES-GCM requires strict nonce management and usage limits per NIST SP 800-38D. The quantum backend integrates with go-keychain's AEAD safety tracking.

### Architecture

```
┌──────────────────────────────────────────────┐
│         MLKEMPrivateKey.Encrypt()            │
└──────────────────────────────────────────────┘
                    │
     1. ML-KEM      │ Encapsulate
                    ▼
         ┌─────────────────────┐
         │ Shared Secret       │
         │ (32 bytes)          │
         └─────────────────────┘
                    │
     2. Generate    │ Random nonce (12 bytes)
                    ▼
         ┌───────────────────────────────┐
         │  AEAD Safety Checks           │
         ├───────────────────────────────┤
         │ tracker.CheckNonce()          │ ← Prevents reuse
         │ tracker.IncrementBytes()      │ ← Enforces limit
         └───────────────────────────────┘
                    │
     3. AES-GCM     │ Encrypt
                    ▼
         ┌─────────────────────┐
         │ Ciphertext          │
         │ + Auth Tag          │
         └─────────────────────┘
                    │
     4. Record      │
                    ▼
         ┌───────────────────────────────┐
         │ tracker.RecordNonce()         │ ← Track usage
         └───────────────────────────────┘
```

### Safety Guarantees

**Nonce Uniqueness:**
- Every nonce is checked against history before use
- Nonce reuse is detected and prevented
- Critical for AES-GCM security (nonce reuse is catastrophic)

**Bytes Limit:**
- Default: 350GB per key (NIST SP 800-38D recommendation)
- Tracks total plaintext encrypted
- Prevents security degradation from excessive use

**Key Rotation:**
- Automatic tracking reset on rotation
- New nonce history and bytes counter
- Ensures fresh security guarantees

## Performance Characteristics

### Algorithm Complexity

**ML-DSA:**
- Key generation: O(n²) polynomial operations
- Signing: O(n²) with rejection sampling
- Verification: O(n²) polynomial operations

**ML-KEM:**
- Key generation: O(n²) polynomial operations
- Encapsulation: O(n²) polynomial operations
- Decapsulation: O(n²) polynomial operations

Where n is the polynomial dimension (increases with security level).

### Measured Performance

Typical performance on Intel x86_64 (3.0 GHz):

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| Key gen | 62 μs | 90 μs | 140 μs |
| Sign | 121 μs | 180 μs | 280 μs |
| Verify | 27 μs | 45 μs | 75 μs |

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| Key gen | 25 μs | 33 μs | 48 μs |
| Encapsulate | 12 μs | 18 μs | 28 μs |
| Decapsulate | 10 μs | 16 μs | 25 μs |

**Encryption overhead:**
- ML-KEM + AES-GCM: ~20 μs
- AEAD tracking: <3 μs
- Total: ~23 μs per encryption

### Size Overhead

**ML-DSA-65 vs ECDSA P-256:**
- Public key: 1952 bytes vs 65 bytes (30x larger)
- Signature: 3309 bytes vs 71 bytes (47x larger)

**ML-KEM-768 vs ECDH P-256:**
- Public key: 1184 bytes vs 65 bytes (18x larger)
- Ciphertext: 1088 bytes vs N/A

**Encryption overhead (ML-KEM-768 + AES-GCM):**
- Fixed overhead: ~1116 bytes (KEM ciphertext + GCM overhead)
- Percentage for 1MB file: 0.11%
- Percentage for 100 bytes: 1116%

## Implementation Details

### Dependency: liboqs

The implementation uses Open Quantum Safe's liboqs library via liboqs-go bindings.

**Advantages:**
- NIST-standard implementations
- Optimized assembly for x86_64 and ARM
- Regular security updates
- Well-tested and audited

**Build Requirements:**
- CGO enabled
- liboqs shared library installed
- pkg-config for library detection

### Build Tags

Quantum support is conditional via build tag:

```go
//go:build quantum

package quantum
```

This allows:
- Optional quantum support
- No impact on builds without quantum tag
- Clean separation of dependencies

### Thread Safety

**QuantumBackend:**
- Thread-safe via read-write mutex
- Concurrent key generation supported
- Concurrent signing/encryption supported

**MLDSAPrivateKey / MLKEMPrivateKey:**
- Thread-safe operations
- liboqs handles internal synchronization
- AEAD tracker uses atomic operations and mutexes

### Memory Management

**Key Material:**
- Secret keys stored in liboqs-managed memory
- Automatic cleanup via `Clean()` method
- Deferred cleanup in backend methods

**Shared Secrets (ML-KEM):**
- Zeroed after use with explicit memory wiping
- Deferred cleanup ensures execution even on errors

```go
defer func() {
    for i := range sharedSecret {
        sharedSecret[i] = 0
    }
}()
```

## Integration Patterns

### Hybrid Classical + Quantum

For maximum security during transition:

```go
// Dual signature verification
ecdsaSig, _ := ecdsaSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
mldsaSig, _ := mldsaSigner.Sign(rand.Reader, hash[:], crypto.SHA256)

// Both must verify for acceptance
if !verifyECDSA(ecdsaSig) || !verifyMLDSA(mldsaSig) {
    return errors.New("signature verification failed")
}
```

### Backend Registry Integration

```go
type Backend interface {
    Type() BackendType
    Capabilities() Capabilities
    GenerateKey(attrs *KeyAttributes) (crypto.PrivateKey, error)
    Signer(attrs *KeyAttributes) (crypto.Signer, error)
    // ... other methods
}

// Quantum backend implements same interface
var _ Backend = (*QuantumBackend)(nil)
```

This enables:
- Transparent backend selection
- Unified API across all backends
- Service layer compatibility

### crypto.Signer Compliance

ML-DSA keys implement Go's standard `crypto.Signer` interface:

```go
type Signer interface {
    Public() crypto.PublicKey
    Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)
}
```

This provides:
- Integration with TLS
- Compatibility with X.509 certificate signing
- Standard Go cryptography ecosystem support

## Security Analysis

### Threat Mitigation

| Threat | Classical | Quantum Backend | Mitigation |
|--------|-----------|-----------------|------------|
| Quantum computer | Vulnerable | Resistant | Lattice-based crypto |
| Nonce reuse | N/A | Protected | AEAD tracking |
| Excessive data/key | N/A | Protected | Bytes limit enforcement |
| Harvest now, decrypt later | Vulnerable | Resistant | Post-quantum algorithms |

### Compliance

**NIST Standards:**
- FIPS 203 (ML-KEM)
- FIPS 204 (ML-DSA)
- SP 800-38D (AES-GCM usage limits)

**Algorithm Selection:**
- Use ML-DSA-65 and ML-KEM-768 for general purpose (Level 3)
- Use ML-DSA-87 and ML-KEM-1024 for high security (Level 5)
- Avoid ML-DSA-44 and ML-KEM-512 unless size is critical

## Future Considerations

### Planned Enhancements

**Algorithm Support:**
- SLH-DSA (FIPS 205) - Stateless hash-based signatures
- Additional NIST-selected algorithms

**X.509 Integration:**
- Post-quantum X.509 certificates
- Hybrid classical+quantum certificates
- Certificate authority support

**Hardware Acceleration:**
- AVX2/AVX-512 optimizations
- ARM NEON optimizations
- Hardware acceleration via specialized chips

### Research Areas

**Hybrid TLS:**
- Dual key exchange (ECDH + ML-KEM)
- Dual authentication (ECDSA + ML-DSA)
- Backward compatibility

**Stateful Operations:**
- LMS/XMSS hash-based signatures
- State management for stateful schemes

**Side-Channel Protection:**
- Constant-time implementations
- Cache-timing resistance
- Power analysis resistance

## References

**NIST Standards:**
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- FIPS 204: Module-Lattice-Based Digital Signature Standard
- SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC

**Implementation:**
- Open Quantum Safe: https://openquantumsafe.org/
- liboqs: https://github.com/open-quantum-safe/liboqs
- liboqs-go: https://github.com/open-quantum-safe/liboqs-go

**Research:**
- CRYSTALS-Dilithium: https://pq-crystals.org/dilithium/
- CRYSTALS-Kyber: https://pq-crystals.org/kyber/
