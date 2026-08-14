# PKCS#11 Module

The PKCS#11 module provides a standard cryptographic token interface to go-xkms, enabling integration with OpenSSL, SSH, NSS, and PKCS#11-aware applications.

## Overview

This module implements OASIS PKCS#11 v3.2 (Cryptoki) as a Go library with SDK transport client connectivity to the go-xkms server. It allows applications to use go-xkms for secure key storage and cryptographic operations through the standard PKCS#11 API.

## Architecture

```
+----------------------------------+
|    PKCS#11 Applications          |
|  (OpenSSL, SSH, pkcs11-tool)     |
+----------------------------------+
              |
              v
+----------------------------------+
|     PKCS#11 Module (Go)          |
|  pkg/pkcs11/module               |
+----------------------------------+
              |
              v (PKCS11Transport - 20 methods)
+----------------------------------+
|     Transport Backend            |
|  gRPC / Unix / Embedded          |
+----------------------------------+
```

The module connects to go-xkms via the `PKCS11Transport` interface -- a minimal 20-method consumer-side interface. The module handles sessions, slots, tokens, objects, mechanisms, digesting, and random generation internally. All existing transports (gRPC, Unix, embedded) satisfy this interface via Go structural typing.

For xkey (standalone mode), the `EmbeddedTransport` provides in-process access to the xkms singleton with zero network overhead and zero stubs.

## Quick Start

### List Slots

```bash
export XKMS_PKCS11_TARGET=unix:///var/run/xkms/xkms.sock
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so --list-slots
```

### Generate RSA Key

```bash
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --login --pin 123456 \
  --keypairgen --key-type rsa:2048 \
  --label "my-signing-key"
```

### Generate EC Key

```bash
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --login --pin 123456 \
  --keypairgen --key-type EC:secp256r1 \
  --label "my-ec-key"
```

### Sign Data

```bash
pkcs11-tool --module /usr/lib/libxkms_pkcs11.so \
  --login --pin 123456 \
  --sign --mechanism RSA-PKCS \
  --label "my-signing-key" \
  --input-file message.txt \
  --output-file signature.bin
```

## Supported Mechanisms

94 mechanisms are registered; **46 are advertised** through `C_GetMechanismList`
(42 in FIPS mode).

| Category | Advertised mechanisms |
|----------|-----------|
| RSA | CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS |
| RSA Signing | CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS |
| RSA PSS | CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS |
| ECDSA | CKM_ECDSA, CKM_ECDSA_SHA1/SHA224/SHA256/SHA384/SHA512 |
| ECDH | CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE |
| EdDSA | CKM_EDDSA |
| AES | CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_GCM, CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP, CKM_AES_KEY_WRAP_PAD |
| Digest | CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA512_224, CKM_SHA512_256 |
| KDF | CKM_HKDF_DERIVE, CKM_HKDF_DATA, CKM_SP800_108_{COUNTER,FEEDBACK,DOUBLE_PIPELINE}_KDF |
| Post-quantum | CKM_ML_KEM, CKM_ML_DSA |
| Key Gen | CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_AES_KEY_GEN, CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_DSA_KEY_PAIR_GEN |

The [support matrix](support-matrix.md) gives every row with its operations,
key-size range and unit, and FIPS status, plus everything registered and
withheld. [deviations.md](deviations.md) covers what the token will not do.
[mechanisms.md](mechanisms.md) has the per-mechanism detail and examples.

## Build Instructions

```bash
# Build the module
make pkcs11

# Run tests
make test-pkcs11

# Install
sudo make install-pkcs11
```

## Documentation

- [Support Matrix](support-matrix.md) - Every mechanism: operations, key sizes, FIPS status
- [Deviations and Limits](deviations.md) - What this token deliberately will not do
- [Consumer Notes](consumers.md) - OpenSSL (provider and ENGINE) and OpenSSH specifics
- [Architecture](architecture.md) - Technical architecture and design
- [Configuration](configuration.md) - Environment variables and config file
- [Usage](usage.md) - Integration examples (OpenSSL, SSH, etc.)
- [Mechanisms](mechanisms.md) - Per-mechanism reference and examples
- [PIV Integration](piv.md) - PIV certificate and key object mapping
- [Security](security.md) - Access control, PIN handling, attribute protection
- [API Reference](api.md) - C API documentation
- [v3.2 Compliance](v32-compliance.md) - PKCS#11 v3.2 function support and PQC mechanisms

## PKCS#11 v3.2 Compliance

This module implements the PKCS#11 v3.2 API surface (all v3.0 and v3.2 function signatures, types, and constants). KEM (encapsulate/decapsulate), authenticated key wrapping, signature-first verification, and the FIPS validation query are implemented and operational; only the three async functions (`C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`) still return `CKR_FUNCTION_NOT_SUPPORTED` pending an async backend. The message-based signature-first verification functions are not yet implemented at all. See [v3.2 Compliance](v32-compliance.md) for the function-by-function status. All v3.0 and earlier functions are fully operational.

### v3.0 Interface Functions
- `C_GetInterfaceList` - List available PKCS#11 interfaces
- `C_GetInterface` - Get a specific interface by name/version

### v3.0 Session Functions
- `C_LoginUser` - Context-specific login with user type
- `C_SessionCancel` - Cancel ongoing cryptographic operations

### v3.0 Message-Based Cryptography (AEAD Support)
Message-based functions enable efficient AEAD (Authenticated Encryption with Associated Data) operations:

| Category | Functions |
|----------|-----------|
| Encrypt | `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`, `C_MessageEncryptFinal` |
| Decrypt | `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`, `C_DecryptMessageNext`, `C_MessageDecryptFinal` |
| Sign | `C_MessageSignInit`, `C_SignMessage`, `C_SignMessageBegin`, `C_SignMessageNext`, `C_MessageSignFinal` |
| Verify | `C_MessageVerifyInit`, `C_VerifyMessage`, `C_VerifyMessageBegin`, `C_VerifyMessageNext`, `C_MessageVerifyFinal` |

### v3.2 Features

All v3.2 functions are defined with correct OASIS-specified signatures and perform input validation (session, mechanism, key handle checks). KEM, authenticated wrapping, signature-first verification (single-part and multi-part), and the validation query are implemented; only the async functions still return `CKR_FUNCTION_NOT_SUPPORTED`.

#### KEM (Key Encapsulation Mechanism) Operations
Post-quantum key agreement through encapsulation/decapsulation:
- `C_EncapsulateKey` - Create a shared secret and ciphertext from a public key
- `C_DecapsulateKey` - Recover a shared secret from ciphertext using a private key

#### Authenticated Key Wrapping
Key export with AEAD confidentiality and integrity protection:
- `C_WrapKeyAuthenticated` - Wrap a key with optional associated data (AAD)
- `C_UnwrapKeyAuthenticated` - Unwrap a key verifying AEAD integrity

#### Signature-First Verification (PQC Streaming)
Signature-first pattern where the signature is provided before data, enabling streaming verification for PQC algorithms:

| Mode | Functions | Status |
|------|-----------|--------|
| Single-part | `C_VerifySignatureInit`, `C_VerifySignature` | Implemented |
| Multi-part | `C_VerifySignatureUpdate`, `C_VerifySignatureFinal` | Implemented |
| Message-based | `C_MessageVerifySignatureInit`, `C_VerifyMessageSignature`, `C_VerifyMessageSignatureBegin`, `C_VerifyMessageSignatureNext`, `C_MessageVerifySignatureFinal` | Not implemented |

#### Async Operations
Non-blocking cryptographic operations identified by function name:
- `C_AsyncComplete` - Retrieve the result of a completed async operation by function name
- `C_AsyncGetID` - Retrieve the operation ID for an async function by name
- `C_AsyncJoin` - Join/await an async operation by function name and ID

#### Validation Framework
FIPS 140-3 and Common Criteria certification support:
- `C_GetSessionValidationFlags` - Query validation status by flags type category

### Post-Quantum Cryptography

The v3.2 PQC mechanisms use standard (non-vendor) values from the OASIS pkcs11t.h header. NIST algorithms (ML-KEM, ML-DSA, SLH-DSA) use the low mechanism range (0x000f-0x003f), while hash-based signature schemes (HSS, XMSS) use the 0x4032-0x4037 range.

**Four are advertised**, both ML-KEM and both ML-DSA; the rest are registered constants without an end-to-end operation and are withheld from `C_GetMechanismList`.

| Algorithm | Standard | Key Gen | Operations | Advertised |
|-----------|----------|---------|------------|------------|
| ML-KEM | FIPS 203 | `CKM_ML_KEM_KEY_PAIR_GEN` (0x0f) | `CKM_ML_KEM` (0x17), encapsulate/decapsulate | **yes** (768, 1024 — not 512) |
| ML-DSA | FIPS 204 | `CKM_ML_DSA_KEY_PAIR_GEN` (0x1c) | `CKM_ML_DSA` (0x1d), sign/verify | **yes** (44, 65, 87) |
| HashML-DSA | FIPS 204 | -- | `CKM_HASH_ML_DSA` (0x1f) + 10 SHA/SHAKE variants (0x23-0x2c) | no |
| SLH-DSA | FIPS 205 | `CKM_SLH_DSA_KEY_PAIR_GEN` (0x2d) | `CKM_SLH_DSA` (0x2e), `CKM_HASH_SLH_DSA` (0x34) + 10 variants (0x36-0x3f) | no |
| HSS/LMS | RFC 8554 | `CKM_HSS_KEY_PAIR_GEN` (0x4032) | `CKM_HSS` (0x4033) | no |
| XMSS | RFC 8391 | `CKM_XMSS_KEY_PAIR_GEN` (0x4034) | `CKM_XMSS` (0x4036) | no |
| XMSS^MT | RFC 8391 | `CKM_XMSSMT_KEY_PAIR_GEN` (0x4035) | `CKM_XMSSMT` (0x4037) | no |

The security level comes from the key object's `CKA_PARAMETER_SET`, not from the mechanism.

`CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE` (0x56), its `_DH` variant (0x57), `CKM_ECDH_X_AES_KEY_WRAP` (0x4038), `CKM_ECDH_COF_AES_KEY_WRAP` (0x4039) and `CKM_PUB_KEY_FROM_PRIV_KEY` (0x403a) keep their constants and names for diagnostics but have **no mechanism descriptor**, so naming one returns `CKR_MECHANISM_INVALID` immediately.

Vendor-defined mechanisms (0x80001xxx, 0x80002xxx) are retained for backward compatibility and are not advertised. Use `GetStandardMechanism()` and `GetStandardKeyType()` to migrate from vendor-defined to standard identifiers.

### Function Count
- **92+ PKCS#11 functions** implemented (all v2.x + v3.0 + v3.2 additions)
- **22 v3.0 functions** for message-based operations and interface discovery (fully operational)
- **12 v3.2 functions** for KEM, authenticated wrapping, signature-first verification, async, and validation -- 9
  implemented (KEM, authenticated wrapping, single/multi-part signature-first verification, validation query), 3
  pending an async backend (`C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`). The 5 message-based
  signature-first functions v3.2 also specifies are not yet implemented.

## PKCS#11 Profiles

The module supports PKCS#11 v3.2 profiles:

| Profile | Description |
|---------|-------------|
| CKP_EXTENDED_PROVIDER | Full mechanism support with authentication |
| CKP_AUTHENTICATION_TOKEN | Signing operations for TLS/SSH authentication |
| CKP_PUBLIC_CERTIFICATES_TOKEN | Certificate storage and retrieval |

## References

- [PKCS#11 v3.2 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [PKCS#11 v3.0 Base Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [PKCS#11 v3.0 Current Mechanisms](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html)
- [PKCS#11 v3.0 Profiles](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/pkcs11-profiles-v3.0.html)

## License

Dual-licensed under AGPL-3.0 and Commercial licenses.
