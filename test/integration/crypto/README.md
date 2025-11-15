# Crypto Package Integration Tests

Comprehensive integration tests for the go-keychain crypto packages.

## Overview

This test suite provides end-to-end integration testing for all cryptographic packages with 90%+ code coverage:

- **pkg/crypto/aead** - AEAD auto-selection, nonce tracking, bytes tracking (94.5% coverage)
- **pkg/crypto/chacha20poly1305** - ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD (90.4% coverage)
- **pkg/crypto/ecies** - ECIES public key encryption (90.3% coverage)
- **pkg/crypto/ecdh** - ECDH key agreement for P-256/P-384/P-521 (91.1% coverage)
- **pkg/crypto/x25519** - X25519 Diffie-Hellman key agreement (91.7% coverage)

## Test Statistics

- **Total Tests**: 195 test cases
- **Total Lines**: 2,564 lines of test code
- **Overall Coverage**: 90%+ across all packages
- **Build Tags**: `integration`

## Running Tests

### Run All Crypto Integration Tests
```bash
go test -v -tags=integration ./test/integration/crypto/...
```

### Run Tests for Specific Package
```bash
# AEAD tests
go test -v -tags=integration ./test/integration/crypto/... -run TestAEAD

# ChaCha20-Poly1305 tests
go test -v -tags=integration ./test/integration/crypto/... -run TestChaCha20Poly1305

# ECIES tests
go test -v -tags=integration ./test/integration/crypto/... -run TestECIES

# ECDH tests
go test -v -tags=integration ./test/integration/crypto/... -run TestECDH

# X25519 tests
go test -v -tags=integration ./test/integration/crypto/... -run TestX25519
```

### Check Coverage
```bash
# Individual package coverage
go test -tags=integration ./pkg/crypto/aead/... -cover
go test -tags=integration ./pkg/crypto/chacha20poly1305/... -cover
go test -tags=integration ./pkg/crypto/ecies/... -cover
go test -tags=integration ./pkg/crypto/ecdh/... -cover
go test -tags=integration ./pkg/crypto/x25519/... -cover
```

### Run Benchmarks
```bash
go test -v -tags=integration -bench=. -benchmem ./test/integration/crypto/...
```

## Test Coverage Details

### AEAD Package (94.5% coverage)
- Algorithm auto-selection (AES-GCM vs ChaCha20-Poly1305)
- Hardware capability detection (AES-NI)
- JWE ↔ Backend algorithm conversion
- Algorithm identification
- Nonce tracker (uniqueness, reuse detection)
- Bytes tracker (usage limits, rotation warnings)
- Concurrent access safety
- Enable/disable tracking

### ChaCha20-Poly1305 Package (90.4% coverage)
- Standard ChaCha20-Poly1305 (12-byte nonce)
- XChaCha20-Poly1305 (24-byte nonce)
- Encryption/decryption operations
- Custom nonce support
- Additional authenticated data (AAD)
- Authentication tag verification
- Tampering detection
- Large data handling
- Multiple encryption uniqueness

### ECIES Package (90.3% coverage)
- P-256, P-384, P-521 curve support
- Ephemeral key generation
- ECDH + HKDF + AES-256-GCM
- Additional authenticated data
- Multiple recipients
- Encryption uniqueness
- Tampering detection
- Invalid input handling
- Cross-curve incompatibility
- Binary data support

### ECDH Package (91.1% coverage)
- P-256, P-384, P-521 curve support
- Shared secret derivation
- HKDF-SHA256 key derivation
- Key separation (different purposes)
- Salt handling
- Curve mismatch detection
- Multi-party key agreement
- Deterministic derivation
- Various key lengths (1-256 bytes)

### X25519 Package (91.7% coverage)
- Key generation (32-byte keys)
- Shared secret derivation
- HKDF-SHA256 key derivation
- Key uniqueness
- Key separation
- Salt and info handling
- Key parsing (import/export)
- Multi-party key agreement
- Deterministic operations
- Various key lengths (1-1024 bytes)

## Test Organization

### Real-World Scenarios
- End-to-end encryption/decryption flows
- Key agreement between multiple parties
- ECIES public key encryption workflows
- AEAD auto-selection based on hardware

### Error Handling
- Invalid inputs (nil, wrong sizes, wrong types)
- Tampering detection
- Authentication failures
- Curve mismatches
- Nonce reuse detection

### Edge Cases
- Empty plaintexts
- Large data (up to 10 MB)
- Binary data patterns
- Self-agreement scenarios
- Concurrent access

### Interoperability
- Multiple curves (P-256, P-384, P-521, X25519)
- Standard and extended nonces
- JWE algorithm compatibility
- Key separation with HKDF

## Performance Testing

Benchmarks are included for critical operations:
- ChaCha20-Poly1305 encrypt/decrypt
- ECIES encrypt/decrypt (by curve)
- ECDH shared secret derivation (by curve)
- HKDF key derivation
- X25519 key generation and agreement

## Test Design Principles

1. **Fast Execution**: All tests run in memory, no disk I/O
2. **No Host Modifications**: Tests never modify the host system
3. **Comprehensive Coverage**: 90%+ code coverage across all packages
4. **Real-World Scenarios**: Tests reflect actual usage patterns
5. **Concurrent Safety**: Tests verify thread-safe operations
6. **Standards Compliance**: Tests verify adherence to RFCs and NIST standards

## Conventions

- Build tag: `//go:build integration`
- Package: `crypto_test` (black-box testing)
- Test functions: `TestPackageName_FeatureName`
- Benchmark functions: `BenchmarkPackageName_FeatureName`
- Use `testify/require` for setup, `testify/assert` for assertions
- All tests must be meaningful and provide regression protection
