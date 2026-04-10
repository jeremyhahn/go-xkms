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

| Category | Mechanisms |
|----------|-----------|
| RSA | CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS |
| RSA Signing | CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS |
| RSA PSS | CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS |
| ECDSA | CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512 |
| AES | CKM_AES_CBC, CKM_AES_GCM, CKM_AES_KEY_WRAP |
| Digest | CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512 |
| Key Gen | CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN, CKM_AES_KEY_GEN |

See [mechanisms.md](mechanisms.md) for detailed mechanism specifications.

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

- [Architecture](architecture.md) - Technical architecture and design
- [Configuration](configuration.md) - Environment variables and config file
- [Usage](usage.md) - Integration examples (OpenSSL, SSH, etc.)
- [Mechanisms](mechanisms.md) - Supported mechanisms reference
- [PIV Integration](piv.md) - PIV certificate and key object mapping
- [API Reference](api.md) - C API documentation
- [v3.2 Compliance](v32-compliance.md) - PKCS#11 v3.2 function support and PQC mechanisms

## PKCS#11 v3.2 Compliance

This module implements the PKCS#11 v3.2 API surface (all v3.0 and v3.2 function signatures, types, and constants). The v3.2 functions currently return `CKR_FUNCTION_NOT_SUPPORTED` pending hardware backend integration. All v3.0 and earlier functions are fully operational.

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

All v3.2 functions are defined with correct OASIS-specified signatures and perform input validation (session, mechanism, key handle checks). They return `CKR_FUNCTION_NOT_SUPPORTED` until KEM/PQC-capable backends are integrated.

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

| Mode | Functions |
|------|-----------|
| Single-part | `C_VerifySignatureInit`, `C_VerifySignature` |
| Multi-part | `C_VerifySignatureUpdate`, `C_VerifySignatureFinal` |
| Message-based | `C_MessageVerifySignatureInit`, `C_VerifyMessageSignature`, `C_VerifyMessageSignatureBegin`, `C_VerifyMessageSignatureNext`, `C_MessageVerifySignatureFinal` |

#### Async Operations
Non-blocking cryptographic operations identified by function name:
- `C_AsyncComplete` - Retrieve the result of a completed async operation by function name
- `C_AsyncGetID` - Retrieve the operation ID for an async function by name
- `C_AsyncJoin` - Join/await an async operation by function name and ID

#### Validation Framework
FIPS 140-3 and Common Criteria certification support:
- `C_GetSessionValidationFlags` - Query validation status by flags type category

### Post-Quantum Cryptography (39 Mechanisms)

The v3.2 PQC mechanisms use standard (non-vendor) values from the OASIS pkcs11t.h header. NIST algorithms (ML-KEM, ML-DSA, SLH-DSA) use the low mechanism range (0x000f-0x003f), while hash-based signature schemes (HSS, XMSS) and ECDH key wrap use the 0x4032-0x403a range.

| Algorithm | Standard | Key Gen | Operations | Hash Variants |
|-----------|----------|---------|------------|---------------|
| ML-KEM | FIPS 203 | `CKM_ML_KEM_KEY_PAIR_GEN` (0x0f) | `CKM_ML_KEM` (0x17) | -- |
| ML-DSA | FIPS 204 | `CKM_ML_DSA_KEY_PAIR_GEN` (0x1c) | `CKM_ML_DSA` (0x1d) | `CKM_HASH_ML_DSA` (0x1f) + 10 SHA/SHAKE variants (0x23-0x2c) |
| SLH-DSA | FIPS 205 | `CKM_SLH_DSA_KEY_PAIR_GEN` (0x2d) | `CKM_SLH_DSA` (0x2e) | `CKM_HASH_SLH_DSA` (0x34) + 10 SHA/SHAKE variants (0x36-0x3f) |
| HSS/LMS | RFC 8554 | `CKM_HSS_KEY_PAIR_GEN` (0x4032) | `CKM_HSS` (0x4033) | -- |
| XMSS | RFC 8391 | `CKM_XMSS_KEY_PAIR_GEN` (0x4034) | `CKM_XMSS` (0x4036) | -- |
| XMSS^MT | RFC 8391 | `CKM_XMSSMT_KEY_PAIR_GEN` (0x4035) | `CKM_XMSSMT` (0x4037) | -- |

Additional v3.2 mechanisms:
- `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE` (0x56), `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH` (0x57)
- `CKM_ECDH_X_AES_KEY_WRAP` (0x4038), `CKM_ECDH_COF_AES_KEY_WRAP` (0x4039)
- `CKM_PUB_KEY_FROM_PRIV_KEY` (0x403a)

Vendor-defined mechanisms (0x80001xxx, 0x80002xxx) are retained for backward compatibility. Use `GetStandardMechanism()` and `GetStandardKeyType()` to migrate from vendor-defined to standard mechanism and key type identifiers.

### Function Count
- **92+ PKCS#11 functions** implemented (all v2.x + v3.0 + v3.2 additions)
- **22 v3.0 functions** for message-based operations and interface discovery (fully operational)
- **16 v3.2 functions** for KEM, authenticated wrapping, signature-first verification, async, and validation (API surface complete, pending backend implementations)

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
