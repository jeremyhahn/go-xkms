# AEAD Auto-Selection

## Overview

The go-keychain library provides intelligent AEAD (Authenticated Encryption with Associated Data) algorithm selection based on hardware capabilities. This ensures optimal performance and security across different CPU architectures and deployment scenarios.

## Algorithm Selection Logic

### Hardware-Backed Keys

For hardware-backed keys (TPM, PKCS#11, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault):
- **Always uses AES-256-GCM**
- Hardware security modules are optimized for AES operations
- Provides the best performance for HSM/TPM/KMS scenarios
- Provides the best security against side-channel / timing attacks.

### Software Keys

For software-based encryption, the algorithm is selected based on CPU capabilities:

#### CPUs with AES-NI Support
- **Uses AES-256-GCM**
- Leverages hardware-accelerated AES instructions
- Provides 2-3x performance improvement over software implementation
- Supported on modern x86_64 and ARM64 processors
- Protects against software AES side-channel attacks

#### CPUs without AES-NI
- **Uses ChaCha20-Poly1305**
- Optimized for constant-time software implementation
- Better performance than software AES
- Resistant to timing attacks

## CPU Detection

The library automatically detects CPU capabilities:

```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"

// Check if CPU has AES-NI support
if aead.HasAESNI() {
    fmt.Println("CPU supports hardware AES acceleration")
}
```

Supported architectures:
- **amd64**: Checks for AES-NI via `cpu.X86.HasAES`
- **arm64**: Checks for AES instructions via `cpu.ARM64.HasAES`
- **Other**: Returns false (uses ChaCha20-Poly1305 for software keys)

## Usage Examples

### JWE Encryption

```go
import "github.com/jeremyhahn/go-keychain/pkg/encoding/jwe"

// Auto-detect optimal algorithm (empty string)
encrypter, err := jwe.NewEncrypter("RSA-OAEP-256", "", publicKey)
if err != nil {
    log.Fatal(err)
}

jweString, err := encrypter.Encrypt(plaintext)
// Uses A256GCM (JWE doesn't support ChaCha20-Poly1305)
```

### Backend Symmetric Encryption

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend"
    "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"
)

// Create key attributes with auto-selection
attrs := &backend.KeyAttributes{
    CN:        "my-encryption-key",
    KeyType:   backend.KEY_TYPE_SECRET,
    StoreType: backend.STORE_SW,
    // KeyAlgorithm is empty - will be auto-selected
}

// Auto-select optimal algorithm
attrs.KeyAlgorithm = backend.SelectOptimalAEAD(attrs)

// Generate the key
key, err := backend.GenerateSymmetricKey(attrs)
```

### Direct Algorithm Selection

```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"

// For software keys - adapts to CPU
softwareAlg := aead.SelectOptimal(false)
// Returns "A256GCM" on AES-NI CPUs
// Returns "ChaCha20-Poly1305" on non-AES-NI CPUs

// For hardware-backed keys - always AES
hardwareAlg := aead.SelectOptimal(true)
// Always returns "A256GCM"
```

### Backend vs JWE Algorithm Names

The library supports two naming conventions:

```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"

// Backend format (lowercase with hyphens)
backendAlg := aead.SelectOptimalBackend(false)
// Returns "aes256-gcm" or "chacha20-poly1305"

// JWE format (uppercase, no hyphens for AES)
jweAlg := aead.SelectOptimal(false)
// Returns "A256GCM" or "ChaCha20-Poly1305"

// Convert between formats
jwe := aead.ToJWE("aes256-gcm")       // "A256GCM"
backend := aead.ToBackend("A256GCM")   // "aes256-gcm"
```

## Explicit Algorithm Override

You can always override auto-selection by specifying an explicit algorithm:

### JWE

```go
// Explicitly use AES-128-GCM
encrypter, err := jwe.NewEncrypter("RSA-OAEP", "A128GCM", publicKey)
```

### Backend

```go
attrs := &backend.KeyAttributes{
    CN:           "my-key",
    KeyType:      backend.KEY_TYPE_SECRET,
    StoreType:    backend.STORE_SW,
    KeyAlgorithm: backend.ALG_CHACHA20_POLY1305, // Explicit
}
```

## Performance Characteristics

### AES-256-GCM with AES-NI
- **Throughput**: 2-4 GB/s (depends on CPU)
- **Latency**: ~50-100 ns per operation
- **Best for**: Hardware-backed keys, CPUs with AES-NI

### ChaCha20-Poly1305 (Software)
- **Throughput**: 500 MB/s - 1 GB/s
- **Latency**: ~100-200 ns per operation
- **Best for**: CPUs without AES-NI, constant-time requirements

### AES-256-GCM (Software, no AES-NI)
- **Throughput**: 100-300 MB/s
- **Latency**: ~500-1000 ns per operation
- **Best for**: JWE compatibility (JWE doesn't support ChaCha20)

## Algorithm Detection Helpers

```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"

// Check algorithm type
if aead.IsAESGCM("A256GCM") {
    // true - it's AES-GCM
}

if aead.IsChaCha("ChaCha20-Poly1305") {
    // true - it's ChaCha
}

// Works with both JWE and backend formats
aead.IsAESGCM("aes256-gcm")        // true
aead.IsChaCha("chacha20-poly1305") // true
```

## Architecture Support

| Architecture | AES-NI Detection | ChaCha20 Support |
|--------------|------------------|------------------|
| amd64        | ✅ Yes           | ✅ Yes           |
| arm64        | ✅ Yes           | ✅ Yes           |
| arm          | ❌ No            | ✅ Yes           |
| 386          | ❌ No            | ✅ Yes           |
| Other        | ❌ No            | ✅ Yes           |

## Best Practices

1. **Use Auto-Selection for Maximum Compatibility**
   - Let the library choose the optimal algorithm for the platform
   - Ensures best performance across heterogeneous deployments

2. **Hardware-Backed Keys Always Use AES**
   - TPM, PKCS#11, and cloud KMS backends are optimized for AES
   - Don't override to ChaCha20 for hardware keys

3. **Test on Target Architecture**
   - Auto-selection adapts to the CPU
   - Test on production-like hardware to verify performance

4. **Explicit Algorithms for Compliance**
   - Use explicit algorithms when regulatory compliance requires specific ciphers
   - Auto-selection may change behavior on different hardware

## Migration Guide

### From Hardcoded AES-256-GCM

Before:
```go
attrs := &backend.KeyAttributes{
    KeyAlgorithm: backend.ALG_AES256_GCM,
    // ...
}
```

After (auto-select):
```go
attrs := &backend.KeyAttributes{
    // KeyAlgorithm omitted or empty
    // ...
}
attrs.KeyAlgorithm = backend.SelectOptimalAEAD(attrs)
```

### From Manual CPU Detection

Before:
```go
var algorithm backend.KeyAlgorithm
if runtime.GOARCH == "amd64" {
    algorithm = backend.ALG_AES256_GCM
} else {
    algorithm = backend.ALG_CHACHA20_POLY1305
}
```

After:
```go
import "github.com/jeremyhahn/go-keychain/pkg/crypto/aead"

algorithm := backend.KeyAlgorithm(aead.SelectOptimalBackend(false))
```

## Troubleshooting

### Algorithm Mismatch Errors

If you get "unsupported algorithm" errors:
- Check that you're using the correct format (JWE vs backend)
- Use `aead.ToJWE()` or `aead.ToBackend()` to convert

### Performance Issues

If encryption is slower than expected:
- Verify AES-NI detection: `aead.HasAESNI()`
- Check if you're using software AES on a CPU without AES-NI
- Consider explicitly using ChaCha20-Poly1305 for software encryption

### JWE ChaCha20 Support

JWE (RFC 7516) does not include ChaCha20-Poly1305 in the standard.
- Auto-selection falls back to A256GCM for JWE
- Use backend symmetric encryption APIs for ChaCha20-Poly1305 support

## References

- [RFC 7516 - JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
- [RFC 7539 - ChaCha20 and Poly1305](https://tools.ietf.org/html/rfc7539)
- [NIST SP 800-38D - GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [golang.org/x/sys/cpu](https://pkg.go.dev/golang.org/x/sys/cpu)
