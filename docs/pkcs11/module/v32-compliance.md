# PKCS#11 v3.2 Compliance

This document details the go-xkms PKCS#11 module's compliance with the OASIS PKCS#11 v3.2 CSD01 specification, covering new function support, post-quantum cryptography mechanisms, parameter sets, and migration guidance.

## v3.2 Function Support Matrix

The module implements all 17 v3.2 function signatures (12 core + 5 message-based VerifySignature) with full input validation, session state management, and proper PKCS#11 size query semantics. Functions that depend on async backend infrastructure return `CKR_FUNCTION_NOT_SUPPORTED` until the corresponding backends are integrated.

| Function | Status | Notes |
|----------|--------|-------|
| `C_EncapsulateKey` | Supported | ML-KEM-768 via crypto/mlkem |
| `C_DecapsulateKey` | Supported | ML-KEM-768 via crypto/mlkem |
| `C_VerifySignatureInit` | Supported | ML-DSA-44 via circl |
| `C_VerifySignature` | Supported | Single-part verification |
| `C_VerifySignatureUpdate` | Supported | Multi-part streaming |
| `C_VerifySignatureFinal` | Supported | Multi-part finalization |
| `C_MessageVerifySignatureInit` | Supported | Message-based session init |
| `C_VerifyMessageSignature` | Supported | Complete message verification |
| `C_VerifyMessageSignatureBegin` | Supported | Streaming message init |
| `C_VerifyMessageSignatureNext` | Supported | Streaming message data |
| `C_MessageVerifySignatureFinal` | Supported | Streaming session cleanup |
| `C_WrapKeyAuthenticated` | Supported | AES-GCM AEAD wrapping with size query support |
| `C_UnwrapKeyAuthenticated` | Supported | AES-GCM AEAD unwrapping with R/W session enforcement |
| `C_GetSessionValidationFlags` | Supported | Returns 0 (non-FIPS module) |
| `C_AsyncComplete` | Not Supported | Returns `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_AsyncGetID` | Not Supported | Returns `CKR_FUNCTION_NOT_SUPPORTED` |
| `C_AsyncJoin` | Not Supported | Returns `CKR_FUNCTION_NOT_SUPPORTED` |

All functions perform input validation (session existence, mechanism presence, key handle validity) before returning results. KEM and AuthWrap functions enforce read-write session requirements for object-creating operations. Size queries (NULL output buffer) return the required buffer length without performing crypto or creating objects.

### CGO Bridge

All v3.2 functions are fully wired through the CGO export layer (`exports_v32.go`) to the Go module layer, with proper C-to-Go type marshaling including:

- `CK_GCM_PARAMS` parsing for AES-GCM mechanism parameters (IV, AAD, tag bits)
- PKCS#11 size query pattern: NULL output pointer returns size without side effects
- `CKF_END_OF_MESSAGE` flag conversion for streaming message operations
- Template and byte buffer marshaling via `convertCTemplateToGo` and `C.GoBytes`

### v3.2 Error Codes

| Constant | Value | Description |
|----------|-------|-------------|
| `CKR_AEAD_DECRYPT_FAILED` | `0x00000042` | AEAD authentication tag verification failed |
| `CKR_OPERATION_CANCEL_FAILED` | `0x00000202` | Async operation cancellation failed |
| `CKR_KEY_EXHAUSTED` | `0x00000203` | Stateful hash-based key usage exhausted |
| `CKR_PENDING` | `0x00000204` | Async operation is pending |
| `CKR_SESSION_ASYNC_NOT_SUPPORTED` | `0x00000205` | Session does not support async |
| `CKR_SEED_RANDOM_REQUIRED` | `0x00000206` | Token requires seed random data |
| `CKR_OPERATION_NOT_VALIDATED` | `0x00000207` | Operation not validated |
| `CKR_OPERATION_INCOMPATIBLE` | `0x00000208` | Operation incompatible with session/token state |
| `CKR_PARAMETER_SET_NOT_SUPPORTED` | `0x00000209` | Parameter set not supported by this token |

## Parameter Set Support (CKP_*)

PKCS#11 v3.2 introduces the `CKA_PARAMETER_SET` attribute to identify PQC security levels. Parameter set values are scoped per key type -- `CKP_ML_DSA_44` and `CKP_ML_KEM_512` both use value `0x00000001` because they apply to different `CKK_*` key types.

### ML-DSA Parameter Sets

| Constant | Value | NIST Category | Security Level |
|----------|-------|---------------|----------------|
| `CKP_ML_DSA_44` | `0x00000001` | 2 | ~128-bit classical |
| `CKP_ML_DSA_65` | `0x00000002` | 3 | ~192-bit classical |
| `CKP_ML_DSA_87` | `0x00000003` | 5 | ~256-bit classical |

### ML-KEM Parameter Sets

| Constant | Value | NIST Category | Security Level |
|----------|-------|---------------|----------------|
| `CKP_ML_KEM_512` | `0x00000001` | 1 | ~128-bit classical |
| `CKP_ML_KEM_768` | `0x00000002` | 3 | ~192-bit classical |
| `CKP_ML_KEM_1024` | `0x00000003` | 5 | ~256-bit classical |

### SLH-DSA Parameter Sets

| Constant | Value | Hash | Security | Speed |
|----------|-------|------|----------|-------|
| `CKP_SLH_DSA_SHA2_128S` | `0x00000001` | SHA2 | 128-bit | Small |
| `CKP_SLH_DSA_SHA2_128F` | `0x00000002` | SHA2 | 128-bit | Fast |
| `CKP_SLH_DSA_SHA2_192S` | `0x00000003` | SHA2 | 192-bit | Small |
| `CKP_SLH_DSA_SHA2_192F` | `0x00000004` | SHA2 | 192-bit | Fast |
| `CKP_SLH_DSA_SHA2_256S` | `0x00000005` | SHA2 | 256-bit | Small |
| `CKP_SLH_DSA_SHA2_256F` | `0x00000006` | SHA2 | 256-bit | Fast |
| `CKP_SLH_DSA_SHAKE_128S` | `0x00000007` | SHAKE | 128-bit | Small |
| `CKP_SLH_DSA_SHAKE_128F` | `0x00000008` | SHAKE | 128-bit | Fast |
| `CKP_SLH_DSA_SHAKE_192S` | `0x00000009` | SHAKE | 192-bit | Small |
| `CKP_SLH_DSA_SHAKE_192F` | `0x0000000A` | SHAKE | 192-bit | Fast |
| `CKP_SLH_DSA_SHAKE_256S` | `0x0000000B` | SHAKE | 256-bit | Small |
| `CKP_SLH_DSA_SHAKE_256F` | `0x0000000C` | SHAKE | 256-bit | Fast |

Parameter set names can be resolved via the `parameterSetNameMap` lookup (e.g., `"ML-DSA-44"` maps to `CKP_ML_DSA_44`).

## PQC Algorithm Support

### Currently Implemented

| Algorithm | NIST Standard | Key Gen | Sign | Verify | Encapsulate | Decapsulate | Implementation |
|-----------|---------------|---------|------|--------|-------------|-------------|----------------|
| ML-DSA-44 | FIPS 204 | Yes | Yes | Yes | -- | -- | circl `mldsa44` |
| ML-DSA-65 | FIPS 204 | Yes | Yes | Yes | -- | -- | circl `mldsa65` |
| ML-DSA-87 | FIPS 204 | Yes | Yes | Yes | -- | -- | circl `mldsa87` |
| ML-KEM-768 | FIPS 203 | Yes | -- | -- | Yes | Yes | Go stdlib `crypto/mlkem` |
| ML-KEM-1024 | FIPS 203 | Yes | -- | -- | Yes | Yes | Go stdlib `crypto/mlkem` |

**ML-DSA key sizes (NIST FIPS 204):**

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| Public key | 1312 bytes | 1952 bytes | 2592 bytes |
| Signature | 2420 bytes | 3309 bytes | 4627 bytes |
| Seed (stored) | 32 bytes | 32 bytes | 32 bytes |

**ML-KEM key sizes (NIST FIPS 203):**

| Parameter | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|-------------|
| Public key (encapsulation key) | 1184 bytes | 1568 bytes |
| Ciphertext | 1088 bytes | 1568 bytes |
| Shared secret | 32 bytes | 32 bytes |
| Seed (stored) | 64 bytes | 64 bytes |

Keys are stored as compact seeds per NIST specifications (FIPS 204 Section 6.1 `ML-DSA.KeyGen(xi)`, FIPS 203 Section 7.1 `ML-KEM.KeyGen(d||z)`). Full keys are deterministically reconstructed from seeds at load time.

### Future Algorithms

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM-512 | FIPS 203 | Not supported (not in Go stdlib `crypto/mlkem`) |
| SLH-DSA | FIPS 205 | Mechanism constants defined, no backend |
| HSS/LMS | RFC 8554 | Mechanism constants defined, no backend |
| XMSS | RFC 8391 | Mechanism constants defined, no backend |
| XMSS^MT | RFC 8391 | Mechanism constants defined, no backend |

PQC operations are always available -- no special build tags are required.

## v3.2 Mechanism Types

The module defines 39 standard v3.2 mechanism constants from the OASIS pkcs11t.h header. NIST algorithms use the low mechanism range (`0x000f`-`0x003f`), while hash-based signature schemes and ECDH key wrap mechanisms use the `0x4032`-`0x403a` range.

### ML-KEM (FIPS 203)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0000000F` | `CKF_GENERATE_KEY_PAIR` |
| `CKM_ML_KEM` | `0x00000017` | `CKF_ENCAPSULATE`, `CKF_DECAPSULATE` |

### ML-DSA (FIPS 204)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x0000001C` | `CKF_GENERATE_KEY_PAIR` |
| `CKM_ML_DSA` | `0x0000001D` | `CKF_SIGN`, `CKF_VERIFY` |

### HashML-DSA (Pre-hashed ML-DSA Variants)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_HASH_ML_DSA` | `0x0000001F` | `CKF_SIGN`, `CKF_VERIFY`, `CKF_MESSAGE_SIGN`, `CKF_MESSAGE_VERIFY` |
| `CKM_HASH_ML_DSA_SHA224` | `0x00000023` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA256` | `0x00000024` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA384` | `0x00000025` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA512` | `0x00000026` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA3_224` | `0x00000027` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA3_256` | `0x00000028` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA3_384` | `0x00000029` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHA3_512` | `0x0000002A` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHAKE128` | `0x0000002B` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_ML_DSA_SHAKE256` | `0x0000002C` | `CKF_SIGN`, `CKF_VERIFY` |

`CKM_HASH_ML_DSA` supports multi-part message-based operations. The hash-specific variants (`SHA224` through `SHAKE256`) are single-part only.

### SLH-DSA (FIPS 205)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_SLH_DSA_KEY_PAIR_GEN` | `0x0000002D` | `CKF_GENERATE_KEY_PAIR` |
| `CKM_SLH_DSA` | `0x0000002E` | `CKF_SIGN`, `CKF_VERIFY` |

### HashSLH-DSA (Pre-hashed SLH-DSA Variants)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_HASH_SLH_DSA` | `0x00000034` | `CKF_SIGN`, `CKF_VERIFY`, `CKF_MESSAGE_SIGN`, `CKF_MESSAGE_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA224` | `0x00000036` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA256` | `0x00000037` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA384` | `0x00000038` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA512` | `0x00000039` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA3_224` | `0x0000003A` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA3_256` | `0x0000003B` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA3_384` | `0x0000003C` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHA3_512` | `0x0000003D` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHAKE128` | `0x0000003E` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_HASH_SLH_DSA_SHAKE256` | `0x0000003F` | `CKF_SIGN`, `CKF_VERIFY` |

### TLS 1.2 Extended Master Key

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE` | `0x00000056` | `CKF_DERIVE` |
| `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH` | `0x00000057` | `CKF_DERIVE` |

### HSS/LMS (RFC 8554)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_HSS_KEY_PAIR_GEN` | `0x00004032` | `CKF_GENERATE_KEY_PAIR` |
| `CKM_HSS` | `0x00004033` | `CKF_SIGN`, `CKF_VERIFY` |

### XMSS / XMSS^MT (RFC 8391)

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_XMSS_KEY_PAIR_GEN` | `0x00004034` | `CKF_GENERATE_KEY_PAIR` |
| `CKM_XMSSMT_KEY_PAIR_GEN` | `0x00004035` | `CKF_GENERATE_KEY_PAIR` |
| `CKM_XMSS` | `0x00004036` | `CKF_SIGN`, `CKF_VERIFY` |
| `CKM_XMSSMT` | `0x00004037` | `CKF_SIGN`, `CKF_VERIFY` |

### ECDH Key Wrap and Utility

| Constant | Value | Capabilities |
|----------|-------|-------------|
| `CKM_ECDH_X_AES_KEY_WRAP` | `0x00004038` | `CKF_WRAP`, `CKF_UNWRAP` |
| `CKM_ECDH_COF_AES_KEY_WRAP` | `0x00004039` | `CKF_WRAP`, `CKF_UNWRAP` |
| `CKM_PUB_KEY_FROM_PRIV_KEY` | `0x0000403A` | `CKF_DERIVE` |

## Async Operations

The three asynchronous operation functions (`C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`) are defined with correct OASIS-specified signatures and perform input validation. All three currently return `CKR_FUNCTION_NOT_SUPPORTED`.

Async operations are identified by function name (string), not by numeric operation ID. This allows applications to query and manage specific async functions by their PKCS#11 name (e.g., `"C_Sign"`).

### Why Not Yet Implemented

Implementing async operations requires:

1. **Per-session async state machine** -- each session must track pending operations, their IDs, and result buffers independently.
2. **Goroutine lifecycle management** -- long-running crypto operations (particularly PQC signing with large keys) must be launched in goroutines and tracked to completion.
3. **CKR_PENDING return code integration** -- existing synchronous functions must be modified to optionally return `CKR_PENDING` when called on async-enabled sessions (`CKF_ASYNC_SESSION`).
4. **Thread safety guarantees** -- result retrieval via `AsyncComplete` and cancellation semantics must be safe for concurrent callers.

These functions will be implemented when PQC hardware backends with inherently long operation times justify non-blocking semantics.

### Related Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CKF_ASYNC_SESSION` | `0x00000008` | Session supports asynchronous operations |
| `CKF_ASYNC_SESSION_SUPPORTED` | `0x04000000` | Token supports asynchronous sessions |
| `CKR_PENDING` | `0x00000204` | Asynchronous operation is pending |
| `CKR_SESSION_ASYNC_NOT_SUPPORTED` | `0x00000205` | Session does not support async |

## Migration Guide

The module retains vendor-defined mechanisms (`0x80001xxx` / `0x80002xxx` range) for backward compatibility while introducing standard v3.2 mechanisms. Applications should migrate to the standard mechanisms for interoperability.

### Mechanism Migration

| Vendor Mechanism | Standard Mechanism |
|------------------|--------------------|
| `CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN` | `CKM_ML_DSA_KEY_PAIR_GEN` + `CKP_ML_DSA_44` |
| `CKM_VENDOR_ML_DSA_44` | `CKM_ML_DSA` + `CKP_ML_DSA_44` |
| `CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN` | `CKM_ML_DSA_KEY_PAIR_GEN` + `CKP_ML_DSA_65` |
| `CKM_VENDOR_ML_DSA_65` | `CKM_ML_DSA` + `CKP_ML_DSA_65` |
| `CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN` | `CKM_ML_DSA_KEY_PAIR_GEN` + `CKP_ML_DSA_87` |
| `CKM_VENDOR_ML_DSA_87` | `CKM_ML_DSA` + `CKP_ML_DSA_87` |
| `CKM_VENDOR_ML_KEM_512_KEY_GEN` | `CKM_ML_KEM_KEY_PAIR_GEN` + `CKP_ML_KEM_512` |
| `CKM_VENDOR_ML_KEM_768_KEY_GEN` | `CKM_ML_KEM_KEY_PAIR_GEN` + `CKP_ML_KEM_768` |
| `CKM_VENDOR_ML_KEM_1024_KEY_GEN` | `CKM_ML_KEM_KEY_PAIR_GEN` + `CKP_ML_KEM_1024` |
| `CKM_VENDOR_ML_KEM_768_ENCAPSULATE` | `CKM_ML_KEM` + `CKP_ML_KEM_768` |
| `CKM_VENDOR_ML_KEM_768_DECAPSULATE` | `CKM_ML_KEM` + `CKP_ML_KEM_768` |

### Key Type Migration

| Vendor Key Type | Standard Key Type |
|-----------------|-------------------|
| `CKK_VENDOR_ML_DSA` (`0x80000001`) | `CKK_ML_DSA` (`0x0000004A`) |
| `CKK_VENDOR_ML_KEM` (`0x80000002`) | `CKK_ML_KEM` (`0x00000049`) |

### Migration Helpers

The module provides two helper functions for automatic mapping:

```go
// Convert a vendor mechanism to its v3.2 standard equivalent
stdMech := module.GetStandardMechanism(module.CKM_VENDOR_ML_DSA_44)
// Returns: CKM_ML_DSA

// Convert a vendor key type to its v3.2 standard equivalent
stdKey := module.GetStandardKeyType(module.CKK_VENDOR_ML_DSA)
// Returns: CKK_ML_DSA
```

Both functions return the input unchanged if no mapping exists, making them safe to call unconditionally.

### Key Difference

The v3.2 standard mechanisms are algorithm-level (e.g., `CKM_ML_DSA` covers all security levels) with the `CKA_PARAMETER_SET` attribute selecting the specific security level. Vendor-defined mechanisms encode the security level in the mechanism itself (e.g., `CKM_VENDOR_ML_DSA_44` is ML-DSA-44 only).

## Build and Dependencies

PQC functionality is always compiled in -- no special build tags are required. The implementation files include:

- `mechanism_quantum.go` -- vendor-defined PQC mechanism constants and registry
- `crypto_quantum.go` -- `QuantumCryptoManager` with ML-DSA and ML-KEM operations
- `module_quantum.go` -- quantum crypto manager initialization
- `mechanism_v32.go` -- v3.2 standard mechanism constants

### Building

```bash
# Build (PQC support included automatically)
go build ./...

# Run tests (PQC tests included automatically)
go test ./pkg/pkcs11/module/...
```

### Dependencies

PQC operations use pure Go libraries with no CGO requirements:

- **ML-DSA**: Cloudflare `circl` (`github.com/cloudflare/circl/sign/mldsa`)
- **ML-KEM**: Go standard library `crypto/mlkem`

## References

- [PKCS#11 v3.2 Specification (OASIS CSD01)](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [NIST FIPS 203 -- ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 -- ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 -- SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 8554 -- HSS/LMS](https://datatracker.ietf.org/doc/html/rfc8554)
- [RFC 8391 -- XMSS](https://datatracker.ietf.org/doc/html/rfc8391)
