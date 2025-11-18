# Quantum-Safe Cryptography Integration Tests

This directory contains comprehensive integration tests for quantum-safe cryptographic algorithms implemented in go-keychain.

## Overview

These tests verify the correct operation of post-quantum cryptographic algorithms:

- **Dilithium2** - Digital signature scheme (NIST PQC standard finalist)
- **Kyber768** - Key Encapsulation Mechanism (NIST PQC standard)

## Prerequisites

### System Dependencies

The tests require the liboqs C library to be installed. You can install it using:

```bash
# Install build dependencies (Debian/Ubuntu)
make deps-quantum-debian

# Build and install liboqs from source
make deps-quantum
```

Or build via Docker (recommended):

```bash
# Run tests in Docker container with all dependencies
make integration-test-quantum
```

## Test Coverage

### Dilithium2 Signature Tests (`dilithium2_integration_test.go`)

- **Key Generation** - Verifies correct key sizes (1312 bytes public, 2560 bytes secret)
- **Signature Workflow** - Tests signing and verification with various message sizes
- **Multiple Signatures** - Signs 100+ messages with single key
- **Key Persistence** - Export/import secret keys
- **Invalid Signatures** - Rejects modified messages, corrupted signatures, wrong keys
- **Concurrent Operations** - Thread safety with 50+ goroutines
- **Performance** - Key generation <100ms, signing/verification <10ms
- **Algorithm Details** - Verifies NIST standard parameters
- **Document Signing** - Real-world signing authority simulation
- **Multiple Key Pairs** - Independent signer isolation

### Kyber768 KEM Tests (`kyber768_integration_test.go`)

- **Key Generation** - Verifies correct key sizes (1184 bytes public, 2400 bytes secret)
- **Encapsulation Workflow** - Complete encap/decap with shared secret verification
- **Multiple Encapsulations** - 100+ encapsulations for single recipient
- **Key Persistence** - Export/import of long-term keys
- **Invalid Ciphertexts** - Rejects empty, truncated, oversized ciphertexts
- **Wrong Key Decapsulation** - Implicit rejection produces different secret
- **Concurrent Operations** - Thread safety with 50+ goroutines
- **Performance** - Key generation <100ms, encap/decap <10ms
- **Algorithm Details** - Verifies NIST standard parameters (32-byte shared secret)
- **Key Exchange Scenarios** - Server/client session establishment
- **Hybrid Encryption** - KEM + AES-256-GCM workflow
- **Multi-Party Exchange** - Multiple receivers with isolation

### Hybrid Cryptography Tests (`hybrid_integration_test.go`)

- **Dual Signatures** - Classical ECDSA + Quantum Dilithium2
- **KEM + AES-GCM** - Kyber key establishment with symmetric encryption
- **Quantum-Resistant TLS Handshake** - Simulated protocol
- **Multi-Layer Security** - Defense-in-depth (ECDSA + Dilithium + Kyber + AES-GCM)
- **Key Rotation** - Old key certifies new quantum key
- **Algorithm Comparison** - Size differences classical vs. quantum

## Running the Tests

### Docker (Recommended)

```bash
# Run all quantum integration tests
make integration-test-quantum

# This will:
# 1. Build a Docker image with liboqs installed
# 2. Run all Dilithium2 tests
# 3. Run all Kyber768 tests
# 4. Run all hybrid tests
# 5. Clean up containers
```

### Local Execution

If you have liboqs installed locally:

```bash
# Or manually:
go test -v -tags="integration quantum" -timeout 30m ./test/integration/quantum/...
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
    dilithium2_integration_test.go:292: Signing: 89.7ms total, 897µs per operation
    dilithium2_integration_test.go:301: Verification: 94.2ms total, 942µs per operation
--- PASS: TestDilithium2Integration_Performance (0.19s)
```

## Build Tags

Tests use Go build constraints:
- `integration` - Standard integration test tag
- `quantum` - Quantum cryptography enabled

Files without `quantum` tag will use stub implementations that return errors.

## Docker Configuration

The test environment uses:
- **Base Image**: `golang:1.25-bookworm`
- **liboqs**: Built from source with CMake + Ninja
- **Compiler**: GCC with OpenSSL development headers
- **Environment Variables**:
  - `CGO_ENABLED=1`
  - `PKG_CONFIG_PATH=/usr/local/lib/pkgconfig`
  - `LD_LIBRARY_PATH=/usr/local/lib`

## Security Considerations

These algorithms are:
- NIST Post-Quantum Cryptography standardization finalists
- Designed to be secure against quantum computer attacks
- Significantly larger than classical counterparts (20-40x for signatures)
- Computationally efficient even with larger sizes

## Known Limitations

1. **macOS/Windows Builds** - Quantum support requires CGO and liboqs, not available in cross-compiled binaries
2. **Key Sizes** - Dilithium2 signatures are ~2.4KB vs ~70 bytes for ECDSA
3. **Memory Usage** - Higher memory footprint due to larger keys
4. **No HSM Support** - Quantum algorithms not yet supported in hardware tokens

## Integration with Keychain API

These tests validate the quantum cryptography primitives. Full integration with the keychain backend storage API is planned for future releases, including:
- Storing quantum key pairs in backends (PKCS8, TPM2, PKCS11)
- Quantum signatures in certificate generation
- Hybrid classical+quantum key derivation
- Quantum-safe secret storage

## Files

- `dilithium2_integration_test.go` - Dilithium2 signature tests (500+ lines)
- `kyber768_integration_test.go` - Kyber768 KEM tests (500+ lines)
- `hybrid_integration_test.go` - Hybrid classical+quantum tests (450+ lines)
- `docker-compose.yml` - Docker Compose configuration
- `Dockerfile` - Test container with liboqs
- `README.md` - This documentation
