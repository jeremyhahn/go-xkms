# Encoding Integration Test Status

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13. The JWK/JWT/JWE integration-test plan this file tracked is complete; the suites live in `test/integration/encoding/`.

## Test Coverage

All four suites carry `//go:build integration`. Counts are top-level `Test*`
functions / `t.Run` subtests, recounted against the code.

### JWK Tests (`jwk_integration_test.go`, 5 / 21)
- Round trips for every key type: RSA 2048/4096, ECDSA P-256/P-384/P-521, Ed25519, X25519, symmetric 128/192/256-bit
- xKMS-backed JWKs: RSA, ECDSA P-256/P-384/P-521, Ed25519
- Error handling: key not found, getter error propagation, empty symmetric key, wrong type for `ToSymmetricKey`
- Indented marshalling
- Complex scenarios: multiple keys in xKMS, public-key export with private-key secrecy

### JWT Tests (`jwt_integration_test.go`, 6 / 28)
- Signing and verification: RS256, RS384, RS512, PS256, ES256, ES384, ES512, EdDSA
- xKMS integration: RSA, ECDSA P-256, Ed25519, auto key ID verification, manual algorithm selection
- Claims validation: standard claims, issuer, single and multiple audiences, custom claims
- Error handling: invalid signature, wrong public key, malformed token, unsupported algorithm, xKMS key not found, empty KID
- Token lifecycle: create, sign, encode, decode, verify
- KID header: sign with KID, extract KID, xKMS KID format

### JWE Tests (`jwe_integration_test.go`, 7 / 27)
- RSA: RSA-OAEP with A256GCM, A128GCM and A256CBC-HS512, RSA-OAEP-256 with A192GCM, algorithm auto-detection
- ECDH-ES: A256KW/A256GCM, A128KW/A128GCM on P-384, auto-detection
- Symmetric: A256KW/A256GCM, A128KW/A128GCM, direct encryption
- xKMS integration: RSA, ECDSA P-256, auto key ID detection, explicit key ID override
- Headers: KID header, multiple headers
- Error handling: wrong decryption key, corrupted ciphertext, invalid JWE format, nil key, unsupported key type, invalid algorithm, xKMS key not found, empty KID
- Payloads: 1 MB and minimal

### Interoperability Tests (`interop_integration_test.go`, 4 / 8)
- JWK → JWT signing (RSA, ECDSA)
- JWK → JWE encryption (RSA-OAEP, ECDH)
- JWT ↔ JWE: encrypted JWT token, nested JWT with different keys
- Full workflow: complete authentication flow, multi-key rotation

## Running

There is no dedicated `integration-test-encoding` target. The suite runs as
part of `make coverage-full`, which passes `./test/integration/encoding/...`
with the tags `integration codec_cbor codec_json codec_msgpack`.

## Implementation Notes

The suites drive a real backend through the helpers in
`test/integration/encoding/helpers_test.go`:
- keys are described with `types.KeyAttributes` (`createRSAAttrs`, `createECDSAAttrs`, `createEd25519Attrs`);
- keys are generated with `backend.GenerateKey(ctx, attrs)` and fetched with `backend.GetKey(ctx, attrs)`;
- `GetKeyByID` resolves a key by common name for the xKMS-backed JWK/JWT/JWE paths.
