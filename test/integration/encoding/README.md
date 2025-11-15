# Encoding Integration Tests

This directory contains integration tests for the encoding packages (JWK, JWT, JWE).

## Test Structure

- `jwk_integration_test.go` - JWK encoding/decoding with software backend
- `jwt_integration_test.go` - JWT signing/verification with software backend  
- `jwe_integration_test.go` - JWE encryption/decryption with software backend
- `interop_integration_test.go` - Interoperability tests between JWK, JWT, and JWE

## Running Tests

```bash
# Run all encoding integration tests
make integration-test-encoding

# Run specific test
go test -v -tags=integration ./test/integration/encoding/... -run TestJWK

# Run with coverage
go test -v -tags=integration -coverprofile=coverage.out ./test/integration/encoding/...
go tool cover -html=coverage.out
```

## Test Coverage

These tests provide comprehensive coverage of:

- All key types (RSA, ECDSA, Ed25519, X25519, symmetric)
- Multiple algorithms for each encoding format
- Keychain integration scenarios
- Error handling and edge cases
- Interoperability between JWK, JWT, and JWE
- Real-world workflows (nested JWTs, encrypted tokens, etc.)

Target coverage: 90%+ for all encoding packages
