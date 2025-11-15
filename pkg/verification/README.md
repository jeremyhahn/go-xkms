# Verification Package

The verification package provides a flexible and comprehensive signature verification implementation supporting multiple cryptographic algorithms and optional integrity checking.

## Features

- **Multiple Algorithm Support**:
  - RSA with PKCS1v15 padding
  - RSA with PSS padding
  - ECDSA with ASN.1 encoding
  - Ed25519

- **Flexible Verification**:
  - Basic verification without options
  - Advanced verification with algorithm-specific options
  - Optional integrity checking against stored checksums

- **Clean API**:
  - Simple verifier interface
  - Extensible checksum provider interface
  - No external dependencies (except standard crypto packages)

## Installation

```bash
go get github.com/jeremyhahn/go-keychain/pkg/verification
```

## Quick Start

### Basic RSA Verification

```go
import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"

    "github.com/jeremyhahn/go-keychain/pkg/verification"
)

// Generate key and sign data
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
hash := crypto.SHA256
hasher := hash.New()
hasher.Write([]byte("message"))
hashed := hasher.Sum(nil)
signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)

// Verify signature
verifier := verification.NewVerifier(nil)
err := verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, nil)
```

### RSA-PSS Verification

```go
import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"

    "github.com/jeremyhahn/go-keychain/pkg/verification"
)

// Sign with PSS
pssOpts := &rsa.PSSOptions{
    SaltLength: rsa.PSSSaltLengthAuto,
    Hash:       crypto.SHA256,
}
signature, _ := rsa.SignPSS(rand.Reader, privateKey, hash, hashed, pssOpts)

// Verify with PSS options
verifier := verification.NewVerifier(nil)
opts := &verification.VerifyOpts{
    KeyAttributes: &verification.KeyAttributes{
        KeyAlgorithm: x509.RSA,
    },
    PSSOptions: pssOpts,
}
err := verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
```

### ECDSA Verification

```go
import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"

    "github.com/jeremyhahn/go-keychain/pkg/verification"
)

// Generate ECDSA key and sign
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hashed)

// Verify
verifier := verification.NewVerifier(nil)
opts := &verification.VerifyOpts{
    KeyAttributes: &verification.KeyAttributes{
        KeyAlgorithm: x509.ECDSA,
    },
}
err := verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
```

### Ed25519 Verification

```go
import (
    "crypto"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"

    "github.com/jeremyhahn/go-keychain/pkg/verification"
)

// Generate Ed25519 key and sign
publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
data := []byte("message")
signature := ed25519.Sign(privateKey, data)

// Verify
verifier := verification.NewVerifier(nil)
opts := &verification.VerifyOpts{
    KeyAttributes: &verification.KeyAttributes{
        KeyAlgorithm: x509.Ed25519,
    },
}
err := verifier.Verify(publicKey, crypto.SHA256, data, signature, opts)
```

### Integrity Checking

The verification package supports optional integrity checking by verifying the digest against a stored checksum:

```go
import (
    "encoding/hex"

    "github.com/jeremyhahn/go-keychain/pkg/verification"
)

// Implement ChecksumProvider interface
type MyChecksumStore struct {
    checksums map[string][]byte
}

func (s *MyChecksumStore) Checksum(opts *verification.VerifyOpts) ([]byte, error) {
    blobName := string(opts.BlobCN)
    return s.checksums[blobName], nil
}

// Use with integrity checking
checksumStore := &MyChecksumStore{
    checksums: map[string][]byte{
        "my-blob": []byte(hex.EncodeToString(hashed)),
    },
}

verifier := verification.NewVerifier(checksumStore)
opts := &verification.VerifyOpts{
    KeyAttributes: &verification.KeyAttributes{
        KeyAlgorithm: x509.RSA,
    },
    BlobCN:         []byte("my-blob"),
    IntegrityCheck: true,
}

err := verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
```

## API Reference

### Interfaces

#### Verifier

```go
type Verifier interface {
    Verify(
        pub crypto.PublicKey,
        hash crypto.Hash,
        hashed, signature []byte,
        opts *VerifyOpts) error
}
```

#### ChecksumProvider

```go
type ChecksumProvider interface {
    Checksum(opts *VerifyOpts) ([]byte, error)
}
```

### Types

#### VerifyOpts

```go
type VerifyOpts struct {
    KeyAttributes  *KeyAttributes
    BlobCN         []byte
    IntegrityCheck bool
    PSSOptions     *rsa.PSSOptions
}
```

#### KeyAttributes

```go
type KeyAttributes struct {
    KeyAlgorithm x509.PublicKeyAlgorithm
    Hash         crypto.Hash
}
```

### Functions

#### NewVerifier

```go
func NewVerifier(checksumProvider ChecksumProvider) Verifier
```

Creates a new verifier instance. The `checksumProvider` is optional and only required if integrity checking will be used.

## Error Handling

The package defines the following errors:

- `ErrInvalidPublicKeyRSA` - Invalid RSA public key type
- `ErrInvalidPublicKeyECDSA` - Invalid ECDSA public key type
- `ErrInvalidPublicKeyEd25519` - Invalid Ed25519 public key type
- `ErrSignatureVerification` - Signature verification failed
- `ErrInvalidSignatureAlgorithm` - Unsupported signature algorithm
- `ErrFileIntegrityCheckFailed` - Integrity check failed
- `ErrInvalidBlobName` - Missing or invalid blob name
- `ErrChecksumNotFound` - Checksum not found

## Testing

The package includes comprehensive tests with 100% code coverage:

```bash
cd /home/jhahn/sources/go-keychain
go test ./pkg/verification/... -v -cover
```

## Design Philosophy

The verification package follows Go best practices:

- **Simple and focused**: Does one thing well
- **Zero dependencies**: Only uses standard library crypto packages
- **Flexible**: Supports multiple algorithms and optional features
- **Type-safe**: Strong typing with clear interfaces
- **Well-tested**: 100% code coverage with comprehensive tests
- **No import cycles**: Standalone package with minimal dependencies

## Performance Considerations

- All cryptographic operations use Go's standard crypto library
- No unnecessary allocations or copies
- Efficient type assertions and algorithm detection
- Minimal overhead for integrity checking (optional)

## Security Considerations

- Always use appropriate hash functions for your security requirements
- RSA keys should be at least 2048 bits
- ECDSA should use P-256 or stronger curves
- Ed25519 provides 128-bit security level
- Integrity checking helps prevent replay and tampering attacks

## License

This package is part of the go-keychain project. See the main project LICENSE file for details.
