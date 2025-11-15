# Shamir's Secret Sharing

A pure Go implementation of Shamir's Secret Sharing Scheme with excellent performance and comprehensive test coverage.

## Overview

Shamir's Secret Sharing is a cryptographic algorithm that divides a secret into N shares, where any M shares (threshold) can reconstruct the original secret, but M-1 or fewer shares reveal absolutely no information about the secret.

## Features

- **Information-theoretically secure**: M-1 shares reveal zero information
- **Flexible threshold**: Configure any M-of-N scheme (1 ≤ M ≤ N ≤ 255)
- **High performance**: Optimized GF(256) arithmetic with lookup tables
- **Integrity checking**: SHA-256 checksums detect share corruption
- **No external dependencies**: Pure Go implementation
- **Comprehensive tests**: 96.5% code coverage

## Installation

```bash
go get github.com/jeremyhahn/go-keychain/pkg/crypto/secretsharing
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/crypto/secretsharing"
)

func main() {
    // Create a 3-of-5 scheme (need 3 shares to reconstruct)
    shamir, err := secretsharing.NewShamir(&secretsharing.ShareConfig{
        Threshold:   3,
        TotalShares: 5,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Split a secret into shares
    secret := []byte("my secret key")
    shares, err := shamir.Split(secret)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Secret split into %d shares\n", len(shares))

    // Reconstruct using any 3 shares
    reconstructed, err := shamir.Combine(shares[:3])
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Secret reconstructed: %s\n", reconstructed)
}
```

## Use Cases

### Multi-Party Authorization

Require multiple executives to approve critical operations:

```go
// Setup: Company needs 3 of 5 executives to approve transactions
shamir, _ := secretsharing.NewShamir(&secretsharing.ShareConfig{
    Threshold:   3,
    TotalShares: 5,
})

masterKey := []byte("master-signing-key")
shares, _ := shamir.Split(masterKey)

// Distribute shares to 5 executives
// executives[i] receives shares[i]

// Later, 3 executives come together to authorize
executiveShares := []secretsharing.Share{
    shares[0], // Executive 1
    shares[2], // Executive 3
    shares[4], // Executive 5
}

reconstructedKey, _ := shamir.Combine(executiveShares)
// Use reconstructedKey to sign the transaction
```

### Backup and Recovery

Distribute backup shares across different locations:

```go
// Create 3-of-5 scheme for backup encryption key
shamir, _ := secretsharing.NewShamir(&secretsharing.ShareConfig{
    Threshold:   3,
    TotalShares: 5,
})

encryptionKey := []byte("backup-encryption-key")
shares, _ := shamir.Split(encryptionKey)

// Store shares in different locations:
// - Share 1: USB drive in safe deposit box
// - Share 2: Printed and stored at home
// - Share 3: Given to trusted family member
// - Share 4: Cloud storage (encrypted)
// - Share 5: Office safe

// To recover, collect any 3 shares
recoveredKey, _ := shamir.Combine(shares[:3])
```

### Secure Key Escrow

Split master keys for secure storage:

```go
// Split SSH private key into shares
shamir, _ := secretsharing.NewShamir(&secretsharing.ShareConfig{
    Threshold:   2,
    TotalShares: 3,
})

sshPrivateKey, _ := os.ReadFile("id_rsa")
shares, _ := shamir.Split(sshPrivateKey)

// Store shares separately
// Reconstruct when needed
reconstructedKey, _ := shamir.Combine(shares[:2])
```

## API Reference

### Types

#### `ShareConfig`

Configuration for secret sharing:

```go
type ShareConfig struct {
    Threshold   int // M - minimum shares needed to reconstruct
    TotalShares int // N - total shares to create
}
```

Constraints:
- `1 <= Threshold <= TotalShares <= 255`

#### `Share`

Represents a single share of a secret:

```go
type Share struct {
    Index    byte   // Share index (1-255)
    Value    []byte // Share value
    Checksum []byte // SHA-256 checksum for integrity
}
```

#### `Shamir`

Main type for secret sharing operations:

```go
type Shamir struct {
    // private fields
}
```

### Functions

#### `NewShamir(config *ShareConfig) (*Shamir, error)`

Creates a new Shamir instance with the given configuration.

**Errors:**
- Config is nil
- Threshold < 1
- TotalShares < Threshold
- TotalShares > 255

#### `(*Shamir) Split(secret []byte) ([]Share, error)`

Divides a secret into N shares requiring M to reconstruct.

**Parameters:**
- `secret`: The data to split (any length)

**Returns:**
- Array of N shares
- Error if secret is empty or random generation fails

**Example:**
```go
shares, err := shamir.Split([]byte("my secret"))
```

#### `(*Shamir) Combine(shares []Share) ([]byte, error)`

Reconstructs the secret from M or more shares.

**Parameters:**
- `shares`: Array of at least M shares

**Returns:**
- The reconstructed secret
- Error if insufficient shares or verification fails

**Example:**
```go
secret, err := shamir.Combine(shares[:3])
```

#### `(*Shamir) Verify(shares []Share) error`

Checks if shares have valid checksums.

**Parameters:**
- `shares`: Array of shares to verify

**Returns:**
- nil if all shares valid
- Error describing which share failed

**Example:**
```go
if err := shamir.Verify(shares); err != nil {
    log.Printf("Invalid share detected: %v", err)
}
```

## Performance

Performance characteristics on modern hardware:

| Secret Size | Split Time | Combine Time |
|-------------|-----------|--------------|
| 32 bytes    | ~2 μs     | ~1 μs        |
| 1 KB        | ~50 μs    | ~30 μs       |
| 1 MB        | ~48 ms    | ~29 ms       |

GF(256) operations:
- Addition: ~0.1 ns
- Multiplication: ~2 ns
- Inverse: ~0.5 ns

## Implementation Details

### Finite Field Arithmetic

All operations are performed in GF(2^8) using:
- **Irreducible polynomial**: x^8 + x^4 + x^3 + x + 1 (0x11B - AES polynomial)
- **Generator**: 0x03
- **Addition/Subtraction**: XOR operation
- **Multiplication**: Logarithm table lookup
- **Division**: Multiply by multiplicative inverse

### Polynomial Interpolation

- **Split**: Creates polynomial p(x) = a₀ + a₁x + ... + aₘ₋₁x^(M-1) where a₀ is the secret
- **Combine**: Uses Lagrange interpolation to find p(0) = secret

### Security

- **Random coefficients**: Generated using `crypto/rand`
- **Information-theoretic security**: Provably secure against unlimited computational power
- **Integrity**: SHA-256 checksums detect tampering

## Testing

Run tests:
```bash
go test ./pkg/crypto/secretsharing/...
```

Run tests with coverage:
```bash
go test ./pkg/crypto/secretsharing/... -cover
```

Run benchmarks:
```bash
go test ./pkg/crypto/secretsharing/... -bench=.
```

## Limitations

- Maximum 255 shares (due to GF(256) field size)
- Share indices 1-255 (index 0 is reserved)
- No compression (shares are same size as secret)
- Single-threaded (no parallel share generation)

## References

- Shamir, A. (1979). "How to Share a Secret". Communications of the ACM. 22 (11): 612–613.
- Blakley, G.R. (1979). "Safeguarding cryptographic keys". Proceedings of the National Computer Conference.
- Finite Field Arithmetic: Stallings, W. (2017). "Cryptography and Network Security". Chapter 4.

## License

Part of the go-keychain project. See LICENSE file for details.

## Contributing

Contributions welcome! Please ensure:
- All tests pass
- Code coverage remains above 90%
- Benchmarks don't regress
- Documentation is updated
