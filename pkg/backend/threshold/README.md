# Threshold Cryptography Backend

The threshold backend implements distributed key management using Shamir Secret Sharing and supports both classical and quantum-safe cryptographic algorithms.

## Overview

Threshold cryptography allows splitting a cryptographic key into **N shares** where any **M shares** can reconstruct the original key or perform cryptographic operations (signing, decryption). This is critical for:

- **Distributed Certificate Authorities**: Multiple nodes must participate in certificate signing
- **Multi-party Authorization**: Require M-of-N approvals for sensitive operations
- **Key Backup**: Distribute key material across multiple secure locations
- **Reduced Single Point of Failure**: No single node can compromise the system

## Supported Algorithms

### Classical Cryptography
- **RSA** (2048+ bit keys)
- **ECDSA** (P-256, P-384, P-521 curves)
- **Ed25519** (Curve25519 signatures)

### Quantum-Safe Cryptography (WITH_QUANTUM=1)
- **ML-DSA-44** (Dilithium2) - NIST PQC Level 2 security
- **ML-DSA-65** (Dilithium3) - NIST PQC Level 3 security
- **ML-DSA-87** (Dilithium5) - NIST PQC Level 5 security

## Architecture

### Shamir Secret Sharing
The backend uses Shamir's Secret Sharing scheme to split private keys:

1. **Key Generation**: Generate a standard private key (RSA, ECDSA, Ed25519, or ML-DSA)
2. **Key Splitting**: Split the key into N shares using polynomial interpolation over finite fields
3. **Share Distribution**: Store each share separately (simulating distribution to N nodes)
4. **Threshold Reconstruction**: Collect M shares to reconstruct the original key
5. **Signing**: Use reconstructed key for cryptographic operations

### Share Storage
```
threshold/
├── metadata/{keyID}     # Key attributes and configuration
└── shares/{keyID}/
    ├── share-1          # Share for participant 1
    ├── share-2          # Share for participant 2
    ├── ...
    └── share-N          # Share for participant N
```

## Usage

### Basic Example (RSA)

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/threshold"
    "github.com/jeremyhahn/go-keychain/pkg/storage/memory"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

// Create threshold backend
storage := memory.New()
config := threshold.DefaultConfig(storage)
backend, err := threshold.NewBackend(config)
if err != nil {
    log.Fatal(err)
}
defer backend.Close()

// Generate a 3-of-5 threshold RSA key
attrs := &types.KeyAttributes{
    CN:           "distributed-ca",
    KeyType:      types.KeyTypeSigning,
    StoreType:    types.StoreThreshold,
    KeyAlgorithm: x509.RSA,
    RSAAttributes: &types.RSAAttributes{
        KeySize: 2048,
    },
    ThresholdAttributes: &types.ThresholdAttributes{
        Threshold:    3,  // Require 3 shares
        Total:        5,  // Split into 5 shares
        Algorithm:    types.ThresholdAlgorithmShamir,
        Participants: []string{"node1", "node2", "node3", "node4", "node5"},
    },
}

// Generate key (automatically splits and stores shares)
privKey, err := backend.GenerateKey(attrs)
if err != nil {
    log.Fatal(err)
}

// Get signer for threshold operations
signer, err := backend.Signer(attrs)
if err != nil {
    log.Fatal(err)
}

// Sign a message (reconstructs key from M shares)
message := []byte("Certificate Signing Request")
hash := sha256.Sum256(message)
signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
```

### Quantum-Safe Example (ML-DSA)

**Note**: Requires building with `WITH_QUANTUM=1`

```go
// Generate a 3-of-5 threshold ML-DSA-44 (Dilithium2) key
attrs := &types.KeyAttributes{
    CN:        "quantum-ca",
    KeyType:   types.KeyTypeSigning,
    StoreType: types.StoreThreshold,
    QuantumAttributes: &types.QuantumAttributes{
        Algorithm: types.QuantumAlgorithmMLDSA44,  // Dilithium2
    },
    ThresholdAttributes: &types.ThresholdAttributes{
        Threshold:    3,
        Total:        5,
        Algorithm:    types.ThresholdAlgorithmShamir,
        Participants: []string{"node1", "node2", "node3", "node4", "node5"},
    },
}

// Generate quantum-safe threshold key
privKey, err := backend.GenerateKey(attrs)
if err != nil {
    log.Fatal(err)
}

// Sign with quantum-safe threshold key
signer, err := backend.Signer(attrs)
if err != nil {
    log.Fatal(err)
}

message := []byte("Quantum-safe certificate")
signature, err := signer.Sign(rand.Reader, message, nil)
```

## Configuration

### ThresholdConfig

```go
type Config struct {
    KeyStorage       storage.Backend  // Required: Storage for key metadata
    ShareStorage     storage.Backend  // Optional: Separate storage for shares
    LocalShareID     int              // This node's share ID (1 to N)
    DefaultThreshold int              // Default M value (must be >= 2)
    DefaultTotal     int              // Default N value (must be >= M)
    DefaultAlgorithm types.ThresholdAlgorithm
    Participants     []string         // Participant identifiers
}
```

### Validation Rules
- `Threshold` must be at least 2
- `Total` must be >= `Threshold`
- Both `Threshold` and `Total` cannot exceed 255
- `Participants` length must match `Total` (if provided)
- `LocalShareID` must be between 1 and `Total`

## Building with Quantum Support

### Standard Build (Classical Algorithms Only)
```bash
go build ./...
```

### Quantum Build (ML-DSA Support)
```bash
go build -tags with_quantum ./...
```

### Environment Variable
```bash
export WITH_QUANTUM=1
go build ./...
```

## Security Considerations

### Strengths
- **No Single Point of Failure**: Compromising M-1 shares reveals nothing about the key
- **Distributed Trust**: Requires cooperation of M participants
- **Quantum Resistance**: ML-DSA algorithms resist quantum computer attacks
- **Perfect Secret Sharing**: Shamir's scheme is information-theoretically secure

### Limitations
- **Key Reconstruction**: Current implementation reconstructs the full key for signing
  - In production, consider threshold signature schemes for better security
- **Share Distribution**: Demo stores all shares locally; production should distribute to N nodes
- **Network Coordination**: Production requires secure communication between nodes
- **Quantum Key Reconstruction**: Simplified implementation for ML-DSA; full liboqs integration needed

### Production Considerations
For a real distributed CA:
1. **Distributed Key Management**: Implement proper threshold protocols (no key reconstruction)
2. **Distributed Storage**: Deploy shares to N independent nodes
3. **Secure Communication**: Use TLS/mTLS for node-to-node coordination
4. **Consensus Protocol**: Implement Byzantine fault tolerance
5. **Audit Logging**: Track all threshold operations
6. **HSM Integration**: Store shares in hardware security modules

## Testing

### Run Standard Tests
```bash
go test ./pkg/backend/threshold/ -v
```

### Run Quantum Tests
```bash
go test -tags with_quantum ./pkg/backend/threshold/ -v
```

### Run Specific Test
```bash
go test ./pkg/backend/threshold/ -v -run TestThresholdSigner_RSA
go test -tags with_quantum ./pkg/backend/threshold/ -v -run TestThresholdSigner_Quantum
```

## Performance

Typical performance on modern hardware:

| Algorithm  | Key Generation | Threshold Split | Signature (K=3) |
|------------|----------------|-----------------|-----------------|
| RSA-2048   | ~100ms         | ~10ms           | ~5ms            |
| ECDSA-P256 | ~1ms           | ~1ms            | ~1ms            |
| Ed25519    | <1ms           | <1ms            | <1ms            |
| ML-DSA-44  | ~2ms           | ~2ms            | ~3ms            |
| ML-DSA-65  | ~3ms           | ~3ms            | ~5ms            |
| ML-DSA-87  | ~5ms           | ~5ms            | ~8ms            |

## Future Enhancements

- [ ] Distributed key generation (DKG)
- [ ] gRPC coordination for multi-node operations
- [ ] Consensus protocol for distributed CA
- [ ] Full ML-DSA secret key import/export
- [ ] Threshold ML-KEM for key encapsulation

## References

- [Shamir's Secret Sharing (1979)](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [liboqs - Open Quantum Safe](https://openquantumsafe.org/)
