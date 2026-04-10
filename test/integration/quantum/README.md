# Quantum-Safe Cryptography Integration Tests

This directory contains comprehensive integration tests for quantum-safe cryptographic algorithms implemented in go-xkms.

## Overview

These tests verify the correct operation of post-quantum cryptographic algorithms using pure-Go implementations:

- **ML-DSA-44** (Dilithium2) - Digital signature scheme (FIPS 204) via cloudflare/circl
- **ML-KEM-768** (Kyber768) - Key Encapsulation Mechanism (FIPS 203) via Go stdlib crypto/mlkem

No CGO or external libraries required.

## Prerequisites

No system-level dependencies needed. The quantum cryptography implementations are pure Go:
- ML-DSA: `github.com/cloudflare/circl/sign/mldsa/mldsa44`
- ML-KEM: `crypto/mlkem` (Go 1.24+ stdlib)

## Test Coverage

### Dilithium2 Signature Tests (`dilithium2_integration_test.go`)

- **Key Generation** - Verifies correct key sizes (1312 bytes public, 32 bytes seed)
- **Signature Workflow** - Tests signing and verification with various message sizes
- **Multiple Signatures** - Signs 100+ messages with single key
- **Key Persistence** - Export/import via seed-based serialization
- **Invalid Signatures** - Rejects modified messages, corrupted signatures, wrong keys
- **Concurrent Operations** - Thread safety with 50+ goroutines
- **Performance** - Key generation <100ms, signing/verification <10ms
- **Algorithm Details** - Verifies NIST FIPS 204 parameters
- **Document Signing** - Real-world signing authority simulation
- **Multiple Key Pairs** - Independent signer isolation

### Kyber768 KEM Tests (`kyber768_integration_test.go`)

- **Key Generation** - Verifies correct key sizes (1184 bytes public, 64 bytes seed)
- **Encapsulation Workflow** - Complete encap/decap with shared secret verification
- **Multiple Encapsulations** - 100+ encapsulations for single recipient
- **Key Persistence** - Export/import via seed-based serialization
- **Invalid Ciphertexts** - Rejects empty, truncated, oversized ciphertexts
- **Wrong Key Decapsulation** - Implicit rejection produces different secret
- **Concurrent Operations** - Thread safety with 50+ goroutines
- **Performance** - Key generation <100ms, encap/decap <10ms
- **Algorithm Details** - Verifies NIST FIPS 203 parameters (32-byte shared secret)
- **Key Exchange Scenarios** - Server/client session establishment
- **Hybrid Encryption** - KEM + AES-256-GCM workflow
- **Multi-Party Exchange** - Multiple receivers with isolation

### Hybrid Cryptography Tests (`hybrid_integration_test.go`)

- **Dual Signatures** - Classical ECDSA + Quantum ML-DSA-44
- **KEM + AES-GCM** - ML-KEM key establishment with symmetric encryption
- **Quantum-Resistant TLS Handshake** - Simulated protocol
- **Multi-Layer Security** - Defense-in-depth (ECDSA + ML-DSA + ML-KEM + AES-GCM)
- **Key Rotation** - Old key certifies new quantum key
- **Algorithm Comparison** - Size differences classical vs. quantum

## Running the Tests

### Docker (Recommended)

```bash
# Run all quantum integration tests
make integration-test-quantum

# This will:
# 1. Build a lightweight Docker image (no external deps needed)
# 2. Run all ML-DSA-44 tests
# 3. Run all ML-KEM-768 tests
# 4. Run all hybrid tests
# 5. Clean up containers
```

### Local Execution

```bash
go test -v -tags="integration" -timeout 30m ./test/integration/quantum/...
```

## Test Output

Expected output includes:
- Key sizes and signature sizes in bytes
- Performance metrics (operations per second)
- Cryptographic parameter verification
- Concurrent operation success rates

Example:
```
=== RUN   TestDilithium2Integration_Performance
    dilithium2_integration_test.go:278: Key generation time: 2.1ms
    dilithium2_integration_test.go:292: Signing: 89.7ms total, 897us per operation
    dilithium2_integration_test.go:301: Verification: 94.2ms total, 942us per operation
--- PASS: TestDilithium2Integration_Performance (0.19s)
```

## Build Tags

Tests use Go build constraints:
- `integration` - Standard integration test tag

Quantum cryptography is always compiled (no build tag required).

## Docker Configuration

The test environment uses:
- **Base Image**: `golang:bookworm`
- **Dependencies**: None beyond Go stdlib and module dependencies
- **CGO**: Not required for quantum operations

## Security Considerations

These algorithms are:
- NIST Post-Quantum Cryptography standards (FIPS 203, FIPS 204)
- Designed to be secure against quantum computer attacks
- Significantly larger than classical counterparts (20-40x for signatures)
- Computationally efficient even with larger sizes

## Known Limitations

1. **Key Sizes** - ML-DSA-44 signatures are ~2.4KB vs ~70 bytes for ECDSA
2. **Memory Usage** - Higher memory footprint due to larger keys
3. **Seed-Based Storage** - Keys stored as compact seeds (32B ML-DSA, 64B ML-KEM), reconstructed on load

## Files

- `dilithium2_integration_test.go` - ML-DSA-44 signature tests
- `kyber768_integration_test.go` - ML-KEM-768 KEM tests
- `hybrid_integration_test.go` - Hybrid classical+quantum tests
- `docker-compose.yml` - Docker Compose configuration
- `Dockerfile` - Lightweight test container
- `README.md` - This documentation
