# Quantum Cryptography Examples

Examples demonstrating post-quantum cryptographic operations using the quantum backend.

## Prerequisites

Quantum support requires:
- Go 1.21+
- liboqs library installed (see [integration test README](../../test/integration/quantum/README.md))
- Build with `quantum` tag

## Quick Start

### Docker (Recommended)

```bash
# Run quantum integration tests (includes liboqs)
make integration-test-quantum
```

### Local Build

```bash
# Install liboqs dependencies
make deps-quantum-debian
make deps-quantum

# Build example
cd examples/quantum/basic-usage
go build -tags="quantum" -o quantum-demo main.go

# Run
./quantum-demo
```

## Examples

### basic-usage/

Comprehensive demonstration of:
- ML-DSA signing (NIST FIPS 204)
- ML-KEM key encapsulation (NIST FIPS 203)
- crypto.Signer interface usage
- Key persistence
- Seamless keychain integration

**Run:**
```bash
cd basic-usage
go run -tags="quantum" main.go
```

**Expected Output:**
```
=== Quantum Cryptography Examples ===

1. Generating ML-DSA-44 key...
   ✓ ML-DSA-44 key generated: mldsa44-signing-key
   Public key: 1312 bytes, Signature: ~2420 bytes

2. Signing with ML-DSA-44...
   ✓ Message signed (2420 bytes)
   ✓ Signature verified successfully

3. Generating ML-DSA-65 key (recommended)...
   ✓ ML-DSA-65 key generated: mldsa65-signing-key
   Public key: 1952 bytes, Signature: ~3309 bytes

4. Generating ML-KEM-768 key...
   ✓ ML-KEM-768 key generated: mlkem768-encryption-key
   Public key: 1184 bytes, Ciphertext: 1088 bytes, Shared secret: 32 bytes

5. Performing key encapsulation...
   ✓ Encapsulation complete
   Ciphertext: 1088 bytes
   Shared secret: 32 bytes (256-bit AES key)
   ✓ Decapsulation complete
   ✓ Shared secrets match - secure channel established

...
```

## Supported Algorithms

### ML-DSA (Digital Signatures)

| Algorithm | Public Key | Signature | Security Level |
|-----------|-----------|-----------|----------------|
| ML-DSA-44 | 1312 bytes | 2420 bytes | NIST Level 2 (AES-128) |
| ML-DSA-65 | 1952 bytes | 3309 bytes | NIST Level 3 (AES-192) ⭐ |
| ML-DSA-87 | 2592 bytes | 4627 bytes | NIST Level 5 (AES-256) |

⭐ Recommended for general use

### ML-KEM (Key Encapsulation)

| Algorithm | Public Key | Ciphertext | Shared Secret | Security Level |
|-----------|-----------|------------|---------------|----------------|
| ML-KEM-512 | 800 bytes | 768 bytes | 32 bytes | NIST Level 1 (AES-128) |
| ML-KEM-768 | 1184 bytes | 1088 bytes | 32 bytes | NIST Level 3 (AES-192) ⭐ |
| ML-KEM-1024 | 1568 bytes | 1568 bytes | 32 bytes | NIST Level 5 (AES-256) |

⭐ Recommended for general use

## Integration Patterns

### Same API as Traditional Backends

```go
// Traditional ECDSA
ecdsaAttrs := &types.KeyAttributes{
    KeyAlgorithm: x509.ECDSA,
    ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
}

// Quantum ML-DSA (same pattern!)
quantumAttrs := &types.KeyAttributes{
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLDSA65,
    },
}

// Both use identical API
key1, _ := backend.GenerateKey(ecdsaAttrs)
key2, _ := backend.GenerateKey(quantumAttrs)
```

### Standard crypto.Signer Interface

```go
// Works with any signing algorithm
signer, _ := backend.Signer(attrs)
signature, _ := signer.Sign(rand.Reader, hash[:], crypto.SHA256)

// ML-DSA implements crypto.Signer just like RSA/ECDSA
```

### Multi-Backend Architecture

```go
// Initialize multiple backends
pkcs8Backend, _ := pkcs8.NewBackend(...)
tpm2Backend, _ := tpm2.NewBackend(...)
quantumBackend, _ := quantum.New(...)

// Use same registry
registry.Register("pkcs8", pkcs8Backend)
registry.Register("tpm2", tpm2Backend)
registry.Register("quantum", quantumBackend)

// Switch backends via configuration
backend := registry.GetBackend("quantum")
```

## Performance

Typical performance on modern hardware:

```
ML-DSA-44:
  Key generation: ~60μs
  Signing: ~120μs
  Verification: ~27μs

ML-DSA-65:
  Key generation: ~90μs
  Signing: ~180μs
  Verification: ~45μs

ML-KEM-768:
  Key generation: ~33μs
  Encapsulation: ~18μs
  Decapsulation: ~16μs
```

## Security Considerations

1. **Quantum Resistance**: ML-DSA and ML-KEM are designed to resist attacks from quantum computers
2. **NIST Standards**: Both are NIST-standardized (FIPS 203, FIPS 204)
3. **Hybrid Security**: Can be combined with classical algorithms for defense-in-depth
4. **Size Trade-offs**: Larger keys/signatures than classical algorithms (20-40x)
5. **Computational Efficiency**: Fast despite larger sizes (~100-200μs operations)

## Use Cases

- **TLS/PKI**: Quantum-safe certificates and TLS connections
- **Code Signing**: Future-proof software signatures
- **IoT Security**: Secure device authentication
- **Hybrid PKI**: Dual classical+quantum signatures
- **Long-term Archives**: Documents that must remain secure for decades

## Further Reading

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [Quantum Usage Guide](../../docs/QUANTUM_USAGE.md)
