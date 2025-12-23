# FROST Threshold Signatures for go-keychain

FROST (Flexible Round-Optimized Schnorr Threshold) signatures enable M-of-N threshold signing where the private key is **never reconstructed**. This implementation is fully compliant with [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/).

## Why FROST?

| Feature | Shamir (existing) | FROST |
|---------|-------------------|-------|
| Key reconstruction | Required for signing | Never required |
| Single point of failure | Yes (during signing) | No |
| Signature type | Any algorithm | Schnorr-based |
| Security model | Honest-but-curious | Malicious with abort |

## Quick Start

### Installation

```bash
# Build with FROST support (enabled by default)
make build

# Or explicitly with the frost tag
go build -tags frost ./...
```

### Generate Keys (Trusted Dealer)

```bash
# Generate 3-of-5 FROST keys using Ed25519
keychain frost keygen \
  --algorithm FROST-Ed25519-SHA512 \
  --threshold 3 \
  --total 5 \
  --participants "alice,bob,charlie,dave,eve" \
  --output ./frost-keys/
```

### Sign a Message (Explicit Rounds)

```bash
# Participant 1: Generate nonces
keychain frost round1 --key-id my-frost-key --output round1-alice.json

# Participant 2: Generate nonces
keychain frost round1 --key-id my-frost-key --output round1-bob.json

# Participant 3: Generate nonces
keychain frost round1 --key-id my-frost-key --output round1-charlie.json

# Each participant: Generate signature share
keychain frost round2 \
  --key-id my-frost-key \
  --message "Hello, FROST!" \
  --commitments round1-alice.json,round1-bob.json,round1-charlie.json \
  --output share-alice.json

# Aggregate signature shares
keychain frost aggregate \
  --key-id my-frost-key \
  --message "Hello, FROST!" \
  --shares share-alice.json,share-bob.json,share-charlie.json \
  --output signature.bin
```

### Verify Signature

```bash
keychain frost verify \
  --key-id my-frost-key \
  --message "Hello, FROST!" \
  --signature signature.bin
```

## Supported Ciphersuites

| Algorithm | Curve | Hash | Use Case |
|-----------|-------|------|----------|
| `FROST-Ed25519-SHA512` | Ed25519 | SHA-512 | General purpose, high performance |
| `FROST-ristretto255-SHA512` | ristretto255 | SHA-512 | Enhanced security properties |
| `FROST-Ed448-SHAKE256` | Ed448 | SHAKE256 | Higher security level (224-bit) |
| `FROST-P256-SHA256` | NIST P-256 | SHA-256 | FIPS compliance |
| `FROST-secp256k1-SHA256` | secp256k1 | SHA-256 | Bitcoin/Ethereum compatibility |

## Go API Quick Start

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
    // Create storage backends
    publicStorage := file.NewBackend("/path/to/frost/public")
    secretBackend := file.NewBackend("/path/to/frost/secret")

    // Create FROST backend
    backend, err := frost.NewBackend(&frost.Config{
        PublicStorage:       publicStorage,
        SecretBackend:       secretBackend,
        Algorithm:           types.FrostAlgorithmEd25519,
        ParticipantID:       1,
        DefaultThreshold:    3,
        DefaultTotal:        5,
        EnableNonceTracking: true,
    })
    if err != nil {
        panic(err)
    }
    defer backend.Close()

    // Generate keys
    attrs := &types.KeyAttributes{
        CN:      "my-frost-key",
        KeyType: types.KeyTypeFrost,
        FrostAttributes: &types.FrostAttributes{
            Threshold:    3,
            Total:        5,
            Algorithm:    types.FrostAlgorithmEd25519,
            Participants: []string{"alice", "bob", "charlie", "dave", "eve"},
        },
    }

    _, err = backend.GenerateKey(attrs)
    if err != nil {
        panic(err)
    }

    fmt.Println("FROST key generated successfully!")
}
```

## Documentation

- [Architecture](architecture.md) - System design and component overview
- [Configuration](configuration.md) - All configuration options
- [Usage](usage.md) - CLI command reference
- [API Reference](api.md) - Go API documentation
- [Backends](backends.md) - Backend-specific setup (TPM, HSM, Cloud KMS)
- [Security](security.md) - Security considerations and best practices
- [DKG Integration](dkg-integration.md) - Implementing custom Distributed Key Generation

## Requirements

- Go 1.25.5 or higher
- go-keychain v0.2.0+
- go-frost library

## License

This module is part of go-keychain and is dual-licensed under AGPL-3.0 and Commercial licenses.
