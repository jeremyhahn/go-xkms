# KDF Adapter

The KDF (Key Derivation Function) adapter provides a clean interface for key derivation in Go applications. It supports multiple industry-standard KDF algorithms.

## Supported Algorithms

- **HKDF** (HMAC-based Extract-and-Expand Key Derivation Function, RFC 5869)
  - Best for deriving keys from high-entropy sources (ECDH, random keys)
  - Fast and efficient
  - Supports optional salt and context information

- **PBKDF2** (Password-Based Key Derivation Function 2, RFC 2898)
  - For password-based key derivation
  - Widely supported and standardized
  - Configurable iteration count
  - Recommended: 600,000 iterations with SHA-256 (OWASP 2023)

- **Argon2** (Winner of the Password Hashing Competition)
  - Best for password-based key derivation (most secure)
  - Two variants: Argon2i (side-channel resistant) and Argon2id (hybrid, recommended)
  - Memory-hard function (resistant to GPU attacks)
  - Configurable memory, time, and parallelism costs

## Usage

### HKDF - Derive Keys from High-Entropy Input

```go
import (
    "crypto"
    _ "crypto/sha256"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/kdf"
)

// Create adapter
adapter := kdf.NewHKDFAdapter()

// Configure parameters
params := &kdf.KDFParams{
    Algorithm: kdf.AlgorithmHKDF,
    Salt:      []byte("random-salt-value"),
    Info:      []byte("application-context"),
    KeyLength: 32,
    Hash:      crypto.SHA256,
}

// Derive key
key, err := adapter.DeriveKey(ikm, params)
```

### PBKDF2 - Derive Keys from Passwords

```go
import (
    "crypto"
    _ "crypto/sha256"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/kdf"
)

// Create adapter
adapter := kdf.NewPBKDF2Adapter()

// Configure parameters
params := &kdf.KDFParams{
    Algorithm:  kdf.AlgorithmPBKDF2,
    Salt:       []byte("random-salt-value"),
    Iterations: 600000, // OWASP recommendation
    KeyLength:  32,
    Hash:       crypto.SHA256,
}

// Derive key from password
key, err := adapter.DeriveKey(password, params)
```

### Argon2id - Secure Password-Based Key Derivation

```go
import "github.com/jeremyhahn/go-keychain/pkg/adapters/kdf"

// Create adapter (Argon2id is recommended)
adapter := kdf.NewArgon2idAdapter()

// Configure parameters
params := &kdf.KDFParams{
    Algorithm: kdf.AlgorithmArgon2id,
    Salt:      []byte("random-salt-value"),
    Memory:    64 * 1024, // 64 MiB
    Time:      3,         // 3 iterations
    Threads:   4,         // 4 parallel threads
    KeyLength: 32,
}

// Derive key from password
key, err := adapter.DeriveKey(password, params)
```

### Using Default Parameters

```go
// Get recommended defaults
params := kdf.DefaultParams(kdf.AlgorithmArgon2id)

// Add salt (should be random and stored)
params.Salt = generateRandomSalt()

adapter := kdf.NewArgon2idAdapter()
key, err := adapter.DeriveKey(password, params)
```

## Algorithm Selection Guide

### Use HKDF When:
- Input has high entropy (cryptographic random keys, ECDH shared secrets)
- You need fast key derivation
- You want to derive multiple keys from one secret
- You need context-specific key binding

### Use PBKDF2 When:
- You need password-based key derivation
- You require FIPS compliance
- You need wide compatibility
- Legacy system support is important

### Use Argon2 When:
- You need password-based key derivation
- Security is the top priority
- You can afford the computational cost
- Protection against GPU attacks is needed
- Use Argon2id (recommended) or Argon2i (side-channel resistant)

## Security Recommendations

### Salts
- Always use a cryptographically random salt
- Minimum 16 bytes (128 bits)
- Store the salt alongside the derived key
- Never reuse salts

### HKDF
- Use SHA-256 or stronger hash functions
- Provide application-specific context in the Info parameter
- Ensure input key material has sufficient entropy

### PBKDF2
- Use at least 600,000 iterations for SHA-256 (OWASP 2023)
- Use at least 210,000 iterations for SHA-512 (OWASP 2023)
- Use SHA-256 or SHA-512

### Argon2
- Recommended: 64 MiB memory, 3 iterations, 4 threads
- Adjust based on your threat model and resources
- Prefer Argon2id for general use
- Use Argon2i if side-channel resistance is critical

## Interface

```go
type KDFAdapter interface {
    // DeriveKey derives a key from input key material
    DeriveKey(ikm []byte, params *KDFParams) ([]byte, error)

    // Algorithm returns the KDF algorithm
    Algorithm() KDFAlgorithm

    // ValidateParams validates parameters
    ValidateParams(params *KDFParams) error
}
```

## Error Handling

The adapter provides specific errors for validation:

- `ErrInvalidSalt` - Salt is nil, empty, or too short
- `ErrInvalidKeyLength` - Key length is invalid or too large
- `ErrInvalidIterations` - Iteration count is too low
- `ErrInvalidMemory` - Memory cost is too low (Argon2)
- `ErrInvalidThreads` - Thread count is invalid (Argon2)
- `ErrInvalidTime` - Time cost is too low (Argon2)
- `ErrInvalidHash` - Hash function is invalid
- `ErrInvalidIKM` - Input key material is invalid
- `ErrUnsupportedAlgorithm` - Algorithm not supported by adapter

## Testing

Run tests:
```bash
go test ./pkg/adapters/kdf/
```

Run benchmarks:
```bash
go test -bench=. -benchmem ./pkg/adapters/kdf/
```

Check coverage:
```bash
go test -cover ./pkg/adapters/kdf/
```

## Performance

Benchmark results on Intel Core Ultra 9 285K:

- **HKDF**: ~1 microsecond per operation (very fast)
- **PBKDF2**: ~10 milliseconds per operation (600k iterations)
- **Argon2id**: ~46 milliseconds per operation (64 MiB, 3 iterations)

## References

- [RFC 5869 - HKDF](https://tools.ietf.org/html/rfc5869)
- [RFC 2898 - PBKDF2](https://tools.ietf.org/html/rfc2898)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
