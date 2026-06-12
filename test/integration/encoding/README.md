# Encoding Integration Tests

This directory contains integration tests for the encoding packages (JWK, JWT, JWE).

## Test Structure

- `jwk_integration_test.go` - JWK encoding/decoding with software backend
- `jwt_integration_test.go` - JWT signing/verification with software backend  
- `jwe_integration_test.go` - JWE encryption/decryption with software backend
- `interop_integration_test.go` - Interoperability tests between JWK, JWT, and JWE

## Running Tests

These tests run as part of the comprehensive coverage target (`make coverage`),
which includes `./test/integration/encoding/...` in its integration step.

```bash
# Run all encoding integration tests
go test -v -tags "integration codec_cbor codec_json codec_msgpack" ./test/integration/encoding/...

# Run specific test
go test -v -tags "integration codec_cbor codec_json codec_msgpack" ./test/integration/encoding/... -run TestJWK

# Run with coverage
go test -v -tags "integration codec_cbor codec_json codec_msgpack" -coverprofile=coverage.out ./test/integration/encoding/...
go tool cover -html=coverage.out
```

## Key ID Convention

All tests use the canonical xkms Key ID format `backend:type:algo:keyname`
(e.g. `software:signing:rsa:jwt-rsa-key`). Key IDs are opaque to the encoding
packages: the jwk/jwt/jwe APIs resolve keys exclusively through injected
getter functions (`jwk.XKMSKeyGetter` / `jwk.XKMSSignerGetter`), never by
parsing kid strings themselves. Key ID parsing and validation are owned by
`pkg/xkms` (`ParseKeyID`/`ValidateKeyID`) and pinned by
`test/integration/xkms/keyid_integration_test.go`.

## Test Coverage

These tests provide comprehensive coverage of:

- All key types (RSA, ECDSA, Ed25519, X25519, symmetric)
- Multiple algorithms for each encoding format
- XKMS integration scenarios
- Error handling and edge cases
- Interoperability between JWK, JWT, and JWE
- Real-world workflows (nested JWTs, encrypted tokens, etc.)

Target coverage: 90%+ for all encoding packages
