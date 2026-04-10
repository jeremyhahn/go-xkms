# PKCS#11 v3.0 to v3.2 Comprehensive Change Inventory

This document provides an exhaustive inventory of every change introduced in PKCS#11 from v3.0 (the baseline) through v3.1 to v3.2.
Source: OASIS PKCS#11 Specification v3.2 CSD01 (`pkcs11-spec-v3.2.html`) and `pkcs11t.h` header file.

---

## Table of Contents

1. [New Constants](#1-new-constants)
2. [New Types and Structures](#2-new-types-and-structures)
3. [New Functions](#3-new-functions)
4. [Modified Functions](#4-modified-functions)
5. [New Mechanism Definitions](#5-new-mechanism-definitions)
6. [New Attributes](#6-new-attributes)
7. [Version and Interface Changes](#7-version-and-interface-changes)
8. [Deprecations](#8-deprecations)
9. [New Object Types](#9-new-object-types)
10. [Post-Quantum Cryptography Details](#10-post-quantum-cryptography-details)

---

## 1. New Constants

### 1.1 New Key Types (CKK_*)

| Constant | Hex Value | Description |
|---|---|---|
| `CKK_HSS` | `0x00000046` | Hash-Based Signatures (LMS/HSS) |
| `CKK_XMSS` | `0x00000047` | Extended Merkle Signature Scheme |
| `CKK_XMSSMT` | `0x00000048` | XMSS Multi-Tree |
| `CKK_ML_KEM` | `0x00000049` | Module-Lattice Key Encapsulation Mechanism (FIPS 203) |
| `CKK_ML_DSA` | `0x0000004A` | Module-Lattice Digital Signature Algorithm (FIPS 204) |
| `CKK_SLH_DSA` | `0x0000004B` | Stateless Hash-Based Digital Signature Algorithm (FIPS 205) |

### 1.2 New Mechanism Types (CKM_*)

#### Post-Quantum KEM Mechanisms

| Constant | Hex Value | Description |
|---|---|---|
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0000000F` | ML-KEM key pair generation |
| `CKM_ML_KEM` | `0x00000017` | ML-KEM encapsulation/decapsulation |

#### Post-Quantum Signature Mechanisms (ML-DSA / Dilithium)

| Constant | Hex Value | Description |
|---|---|---|
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x0000001C` | ML-DSA key pair generation |
| `CKM_ML_DSA` | `0x0000001D` | ML-DSA pure signing/verification |
| `CKM_HASH_ML_DSA` | `0x0000001F` | ML-DSA pre-hashed (HashML-DSA) |
| `CKM_HASH_ML_DSA_SHA224` | `0x00000023` | HashML-DSA with SHA-224 |
| `CKM_HASH_ML_DSA_SHA256` | `0x00000024` | HashML-DSA with SHA-256 |
| `CKM_HASH_ML_DSA_SHA384` | `0x00000025` | HashML-DSA with SHA-384 |
| `CKM_HASH_ML_DSA_SHA512` | `0x00000026` | HashML-DSA with SHA-512 |
| `CKM_HASH_ML_DSA_SHA3_224` | `0x00000027` | HashML-DSA with SHA3-224 |
| `CKM_HASH_ML_DSA_SHA3_256` | `0x00000028` | HashML-DSA with SHA3-256 |
| `CKM_HASH_ML_DSA_SHA3_384` | `0x00000029` | HashML-DSA with SHA3-384 |
| `CKM_HASH_ML_DSA_SHA3_512` | `0x0000002A` | HashML-DSA with SHA3-512 |
| `CKM_HASH_ML_DSA_SHAKE128` | `0x0000002B` | HashML-DSA with SHAKE128 |
| `CKM_HASH_ML_DSA_SHAKE256` | `0x0000002C` | HashML-DSA with SHAKE256 |

#### Post-Quantum Signature Mechanisms (SLH-DSA / SPHINCS+)

| Constant | Hex Value | Description |
|---|---|---|
| `CKM_SLH_DSA_KEY_PAIR_GEN` | `0x0000002D` | SLH-DSA key pair generation |
| `CKM_SLH_DSA` | `0x0000002E` | SLH-DSA pure signing/verification |
| `CKM_HASH_SLH_DSA` | `0x00000034` | SLH-DSA pre-hashed (HashSLH-DSA) |
| `CKM_HASH_SLH_DSA_SHA224` | `0x00000036` | HashSLH-DSA with SHA-224 |
| `CKM_HASH_SLH_DSA_SHA256` | `0x00000037` | HashSLH-DSA with SHA-256 |
| `CKM_HASH_SLH_DSA_SHA384` | `0x00000038` | HashSLH-DSA with SHA-384 |
| `CKM_HASH_SLH_DSA_SHA512` | `0x00000039` | HashSLH-DSA with SHA-512 |
| `CKM_HASH_SLH_DSA_SHA3_224` | `0x0000003A` | HashSLH-DSA with SHA3-224 |
| `CKM_HASH_SLH_DSA_SHA3_256` | `0x0000003B` | HashSLH-DSA with SHA3-256 |
| `CKM_HASH_SLH_DSA_SHA3_384` | `0x0000003C` | HashSLH-DSA with SHA3-384 |
| `CKM_HASH_SLH_DSA_SHA3_512` | `0x0000003D` | HashSLH-DSA with SHA3-512 |
| `CKM_HASH_SLH_DSA_SHAKE128` | `0x0000003E` | HashSLH-DSA with SHAKE128 |
| `CKM_HASH_SLH_DSA_SHAKE256` | `0x0000003F` | HashSLH-DSA with SHAKE256 |

#### Hash-Based Stateful Signature Mechanisms (HSS/LMS, XMSS)

| Constant | Hex Value | Description |
|---|---|---|
| `CKM_HSS_KEY_PAIR_GEN` | `0x00004032` | HSS/LMS key pair generation |
| `CKM_HSS` | `0x00004033` | HSS/LMS signing/verification |
| `CKM_XMSS_KEY_PAIR_GEN` | `0x00004034` | XMSS key pair generation |
| `CKM_XMSSMT_KEY_PAIR_GEN` | `0x00004035` | XMSS^MT key pair generation |
| `CKM_XMSS` | `0x00004036` | XMSS signing/verification |
| `CKM_XMSSMT` | `0x00004037` | XMSS^MT signing/verification |

#### Other New Mechanisms

| Constant | Hex Value | Description |
|---|---|---|
| `CKM_ECDH_X_AES_KEY_WRAP` | `0x00004038` | ECDH Montgomery AES key wrapping (replaces deprecated `CKM_ECDH_AES_KEY_WRAP` for Montgomery keys) |
| `CKM_ECDH_COF_AES_KEY_WRAP` | `0x00004039` | ECDH cofactor AES key wrapping |
| `CKM_PUB_KEY_FROM_PRIV_KEY` | `0x0000403A` | Derive a public key object from a private key |

### 1.3 New Attribute Types (CKA_*)

| Constant | Hex Value | Data Type | Description |
|---|---|---|---|
| `CKA_PARAMETER_SET` | `0x0000061D` | `CK_*_PARAMETER_SET_TYPE` | Selects the parameter set for PQC algorithms (ML-DSA, ML-KEM, SLH-DSA, XMSS, XMSS^MT) |
| `CKA_OBJECT_VALIDATION_FLAGS` | `0x0000061E` | `CK_FLAGS` | Validation flags for key objects (FIPS validation indicators) |
| `CKA_HSS_LEVELS` | `0x00000617` | `CK_ULONG` | Number of HSS levels (1-8) |
| `CKA_HSS_LMS_TYPE` | `0x00000618` | `CK_ULONG` | LMS type for single-level HSS public keys |
| `CKA_HSS_LMOTS_TYPE` | `0x00000619` | `CK_ULONG` | LMOTS type for single-level HSS public keys |
| `CKA_HSS_LMS_TYPES` | `0x0000061A` | `Byte array` | Array of LMS types (one per level, for HSS private keys) |
| `CKA_HSS_LMOTS_TYPES` | `0x0000061B` | `Byte array` | Array of LMOTS types (one per level, for HSS private keys) |
| `CKA_HSS_KEYS_REMAINING` | `0x0000061C` | `CK_ULONG` | Number of remaining one-time signatures for HSS private key |
| `CKA_ENCAPSULATE` | `0x00000633` | `CK_BBOOL` | Whether public key supports KEM encapsulation (used with `C_EncapsulateKey`) |
| `CKA_DECAPSULATE` | `0x00000634` | `CK_BBOOL` | Whether private key supports KEM decapsulation (used with `C_DecapsulateKey`) |
| `CKA_SEED` | `0x00000637` | `Byte array` | Seed value for deterministic key generation (ML-DSA, ML-KEM private keys) |

#### Validation Object Attributes (CKA_VALIDATION_*)

| Constant | Description |
|---|---|
| `CKA_VALIDATION_TYPE` | Type of validation (e.g., FIPS 140) |
| `CKA_VALIDATION_VERSION` | Version of the validation standard |
| `CKA_VALIDATION_LEVEL` | Security level of validation |
| `CKA_VALIDATION_MODULE_ID` | Identifier of the validated module |
| `CKA_VALIDATION_FLAG` | Validation-specific flags |
| `CKA_VALIDATION_AUTHORITY_TYPE` | Type of validation authority |
| `CKA_VALIDATION_COUNTRY` | Country of validation |
| `CKA_VALIDATION_CERTIFICATE_IDENTIFIER` | Certificate identifier for the validation |
| `CKA_VALIDATION_CERTIFICATE_URI` | URI to validation certificate |
| `CKA_VALIDATION_VENDOR_URI` | URI to vendor validation page |
| `CKA_VALIDATION_PROFILE` | Validation profile |

#### Trust Object Attributes (CKA_TRUST_*)

| Constant | Description |
|---|---|
| `CKA_TRUST_SERVER_AUTH` | Trust for TLS server authentication |
| `CKA_TRUST_CLIENT_AUTH` | Trust for TLS client authentication |
| `CKA_TRUST_CODE_SIGNING` | Trust for code signing |
| `CKA_TRUST_EMAIL_PROTECTION` | Trust for email protection (S/MIME) |
| `CKA_TRUST_IPSEC_IKE` | Trust for IPsec IKE |
| `CKA_TRUST_TIME_STAMPING` | Trust for time stamping |
| `CKA_TRUST_OCSP_SIGNING` | Trust for OCSP response signing |

### 1.4 New Object Classes (CKO_*)

| Constant | Hex Value | Description |
|---|---|---|
| `CKO_VALIDATION` | `0x0000000A` | Validation objects - represent FIPS 140 and other validation information |
| `CKO_TRUST` | `0x0000000B` | Trust objects - represent trust decisions for certificates |

### 1.5 New Mechanism Capability Flags (CKF_*)

| Constant | Hex Value | Context | Description |
|---|---|---|---|
| `CKF_ENCAPSULATE` | `0x10000000` | `CK_MECHANISM_INFO.flags` | Mechanism can be used with `C_EncapsulateKey` |
| `CKF_DECAPSULATE` | `0x20000000` | `CK_MECHANISM_INFO.flags` | Mechanism can be used with `C_DecapsulateKey` |
| `CKF_FIND_OBJECTS` | `0x00000040` | `CK_MECHANISM_INFO.flags` | Mechanism supports object search (v3.1) |
| `CKF_MULTI_MESSAGE` | `0x00000020` | `CK_MECHANISM_INFO.flags` | Mechanism supports multi-message operations (v3.1) |
| `CKF_ASYNC_SESSION` | `0x00000008` | `CK_SESSION_INFO.flags` | Session supports asynchronous operations |
| `CKF_ASYNC_SESSION_SUPPORTED` | `0x04000000` | `CK_TOKEN_INFO.flags` | Token supports asynchronous sessions |
| `CKF_SEED_RANDOM_REQUIRED` | `0x02000000` | `CK_TOKEN_INFO.flags` | Token requires seeding before `C_GenerateRandom` |
| `CKF_INTERFACE_FORK_SAFE` | `0x00000001` | `CK_INTERFACE.flags` | Interface is fork-safe (v3.1) |

### 1.6 New Return Codes (CKR_*)

| Constant | Hex Value | Description |
|---|---|---|
| `CKR_AEAD_DECRYPT_FAILED` | `0x00000042` | AEAD authentication tag verification failed during decryption |
| `CKR_OPERATION_CANCEL_FAILED` | `0x00000202` | Attempt to cancel an operation that cannot be cancelled |
| `CKR_KEY_EXHAUSTED` | `0x00000203` | Stateful signature key has no remaining signatures (HSS/XMSS) |
| `CKR_PENDING` | `0x00000204` | Asynchronous operation is still in progress |
| `CKR_SESSION_ASYNC_NOT_SUPPORTED` | `0x00000205` | Token does not support asynchronous sessions |
| `CKR_SEED_RANDOM_REQUIRED` | `0x00000206` | `C_SeedRandom` must be called before `C_GenerateRandom` |
| `CKR_OPERATION_NOT_VALIDATED` | `0x00000207` | Operation violates validation policy/FIPS mode constraints |
| `CKR_PARAMETER_SET_NOT_SUPPORTED` | `0x00000209` | Requested parameter set (e.g., ML-KEM-768) is not supported by this token |

### 1.7 New Parameter Set Constants (CKP_*)

#### ML-DSA Parameter Sets (FIPS 204)

| Constant | Description | NIST Security Level |
|---|---|---|
| `CKP_ML_DSA_44` | ML-DSA-44 parameter set | Level 2 |
| `CKP_ML_DSA_65` | ML-DSA-65 parameter set | Level 3 |
| `CKP_ML_DSA_87` | ML-DSA-87 parameter set | Level 5 |

#### ML-KEM Parameter Sets (FIPS 203)

| Constant | Description | NIST Security Level |
|---|---|---|
| `CKP_ML_KEM_512` | ML-KEM-512 parameter set | Level 1 |
| `CKP_ML_KEM_768` | ML-KEM-768 parameter set | Level 3 |
| `CKP_ML_KEM_1024` | ML-KEM-1024 parameter set | Level 5 |

#### SLH-DSA Parameter Sets (FIPS 205)

| Constant | Hash | Security Level | Variant |
|---|---|---|---|
| `CKP_SLH_DSA_SHA2_128S` | SHA-256 | 128-bit | Small (slow sign, small sig) |
| `CKP_SLH_DSA_SHAKE_128S` | SHAKE256 | 128-bit | Small |
| `CKP_SLH_DSA_SHA2_128F` | SHA-256 | 128-bit | Fast (fast sign, large sig) |
| `CKP_SLH_DSA_SHAKE_128F` | SHAKE256 | 128-bit | Fast |
| `CKP_SLH_DSA_SHA2_192S` | SHA-256 | 192-bit | Small |
| `CKP_SLH_DSA_SHAKE_192S` | SHAKE256 | 192-bit | Small |
| `CKP_SLH_DSA_SHA2_192F` | SHA-256 | 192-bit | Fast |
| `CKP_SLH_DSA_SHAKE_192F` | SHAKE256 | 192-bit | Fast |
| `CKP_SLH_DSA_SHA2_256S` | SHA-256 | 256-bit | Small |
| `CKP_SLH_DSA_SHAKE_256S` | SHAKE256 | 256-bit | Small |
| `CKP_SLH_DSA_SHA2_256F` | SHA-256 | 256-bit | Fast |
| `CKP_SLH_DSA_SHAKE_256F` | SHAKE256 | 256-bit | Fast |

---

## 2. New Types and Structures

### 2.1 CK_FUNCTION_LIST_3_2

New function list structure extending `CK_FUNCTION_LIST_3_0` with additional function pointers.

```c
typedef struct CK_FUNCTION_LIST_3_2 {
  CK_VERSION version;                          // Must be >= {3, 2}
  // ... all functions from CK_FUNCTION_LIST_3_0 ...
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  // Message-based encrypt/decrypt (from v3.1)
  CK_C_MessageEncryptInit C_MessageEncryptInit;
  CK_C_EncryptMessage C_EncryptMessage;
  CK_C_EncryptMessageBegin C_EncryptMessageBegin;
  CK_C_EncryptMessageNext C_EncryptMessageNext;
  CK_C_MessageEncryptFinal C_MessageEncryptFinal;
  CK_C_MessageDecryptInit C_MessageDecryptInit;
  CK_C_DecryptMessage C_DecryptMessage;
  CK_C_DecryptMessageBegin C_DecryptMessageBegin;
  CK_C_DecryptMessageNext C_DecryptMessageNext;
  CK_C_MessageDecryptFinal C_MessageDecryptFinal;
  // Message-based sign/verify (from v3.1)
  CK_C_MessageSignInit C_MessageSignInit;
  CK_C_SignMessage C_SignMessage;
  CK_C_SignMessageBegin C_SignMessageBegin;
  CK_C_SignMessageNext C_SignMessageNext;
  CK_C_MessageSignFinal C_MessageSignFinal;
  CK_C_MessageVerifyInit C_MessageVerifyInit;
  CK_C_VerifyMessage C_VerifyMessage;
  CK_C_VerifyMessageBegin C_VerifyMessageBegin;
  CK_C_VerifyMessageNext C_VerifyMessageNext;
  CK_C_MessageVerifyFinal C_MessageVerifyFinal;
  // NEW in v3.2: KEM operations
  CK_C_EncapsulateKey C_EncapsulateKey;
  CK_C_DecapsulateKey C_DecapsulateKey;
  // NEW in v3.2: Signature-first verify
  CK_C_VerifySignatureInit C_VerifySignatureInit;
  CK_C_VerifySignature C_VerifySignature;
  CK_C_VerifySignatureUpdate C_VerifySignatureUpdate;
  CK_C_VerifySignatureFinal C_VerifySignatureFinal;
  // NEW in v3.2: Validation flags
  CK_C_GetSessionValidationFlags C_GetSessionValidationFlags;
  // NEW in v3.2: Asynchronous operations
  CK_C_AsyncComplete C_AsyncComplete;
  CK_C_AsyncGetID C_AsyncGetID;
  CK_C_AsyncJoin C_AsyncJoin;
  // NEW in v3.2: Authenticated wrap/unwrap
  CK_C_WrapKeyAuthenticated C_WrapKeyAuthenticated;
  CK_C_UnwrapKeyAuthenticated C_UnwrapKeyAuthenticated;
} CK_FUNCTION_LIST_3_2;
```

### 2.2 CK_ASYNC_DATA

Structure for passing results from asynchronous operations.

```c
typedef struct CK_ASYNC_DATA {
  CK_ULONG ulVersion;              // Version of this structure
  CK_BYTE_PTR pValue;              // Receives output data
  CK_ULONG ulValue;                // Length of output data
  CK_OBJECT_HANDLE hObject;        // Receives resulting object handle
  CK_OBJECT_HANDLE hAdditionalObject; // Receives additional object handle
} CK_ASYNC_DATA;
```

### 2.3 CK_SESSION_VALIDATION_FLAGS_TYPE

Type for querying session validation flags (FIPS indicators).

```c
typedef CK_ULONG CK_SESSION_VALIDATION_FLAGS_TYPE;
```

### 2.4 Post-Quantum Parameter Set Types

```c
typedef CK_ULONG CK_ML_DSA_PARAMETER_SET_TYPE;    // ML-DSA parameter sets
typedef CK_ULONG CK_ML_KEM_PARAMETER_SET_TYPE;    // ML-KEM parameter sets
typedef CK_ULONG CK_SLH_DSA_PARAMETER_SET_TYPE;   // SLH-DSA parameter sets
typedef CK_ULONG CK_XMSS_PARAMETER_SET_TYPE;      // XMSS parameter sets
typedef CK_ULONG CK_XMSSMT_PARAMETER_SET_TYPE;    // XMSS^MT parameter sets
```

### 2.5 CK_SP800_108_KEY_HANDLE

Type for SP800-108 KDF key handles (renamed from `CK_KEY_HANDLE` in WD09).

---

## 3. New Functions

### 3.1 C_EncapsulateKey (KEM Encapsulation)

```c
CK_DECLARE_FUNCTION(CK_RV, C_EncapsulateKey)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_MECHANISM_PTR pMechanism,       // KEM mechanism
  CK_OBJECT_HANDLE hPublicKey,       // Encapsulation (public) key
  CK_ATTRIBUTE_PTR pTemplate,        // Template for the resulting secret key
  CK_ULONG ulAttributeCount,        // Number of attributes in template
  CK_BYTE_PTR pCiphertext,          // Output: ciphertext (encapsulated key)
  CK_ULONG_PTR pulCiphertextLen,    // Output: ciphertext length
  CK_OBJECT_HANDLE_PTR phKey        // Output: handle to new secret key
);
```

- **Purpose**: Creates a new shared secret key by encapsulating against a public key using a KEM. Returns both the new key object and the ciphertext needed for decapsulation.
- **Key requirement**: `CKA_ENCAPSULATE` on the public key must be `CK_TRUE`.
- **New key properties**: `CKA_ALWAYS_SENSITIVE=CK_FALSE`, `CKA_NEVER_EXTRACTABLE=CK_FALSE`, `CKA_LOCAL=CK_FALSE`.
- **Return values include**: `CKR_BUFFER_TOO_SMALL`, `CKR_PARAMETER_SET_NOT_SUPPORTED`.

### 3.2 C_DecapsulateKey (KEM Decapsulation)

```c
CK_DECLARE_FUNCTION(CK_RV, C_DecapsulateKey)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_MECHANISM_PTR pMechanism,       // KEM mechanism
  CK_OBJECT_HANDLE hPrivateKey,      // Decapsulation (private) key
  CK_ATTRIBUTE_PTR pTemplate,        // Template for the resulting secret key
  CK_ULONG ulAttributeCount,        // Number of attributes in template
  CK_BYTE_PTR pCiphertext,          // Input: ciphertext from encapsulation
  CK_ULONG ulCiphertextLen,         // Input: ciphertext length
  CK_OBJECT_HANDLE_PTR phKey        // Output: handle to decapsulated secret key
);
```

- **Purpose**: Recovers the shared secret key from a ciphertext using a private key. The resulting key is identical to the one produced by the corresponding `C_EncapsulateKey` call.
- **Key requirement**: `CKA_DECAPSULATE` on the private key must be `CK_TRUE`.
- **Return values include**: `CKR_PARAMETER_SET_NOT_SUPPORTED`.

### 3.3 C_VerifySignatureInit (Signature-First Verify Init)

```c
CK_DECLARE_FUNCTION(CK_RV, C_VerifySignatureInit)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_MECHANISM_PTR pMechanism,       // Verification mechanism
  CK_OBJECT_HANDLE hKey,             // Verification (public) key handle
  CK_BYTE_PTR pSignature,           // Signature to verify
  CK_ULONG ulSignatureLen           // Signature length
);
```

- **Purpose**: Initializes a verification operation where the **signature is provided at init time** rather than at the end. This enables streaming verification of large data against a known signature.
- **Key requirement**: `CKA_VERIFY` must be `CK_TRUE`.
- Any mechanism supporting `C_VerifyInit` must also support `C_VerifySignatureInit`.
- Can be called with `pMechanism=NULL_PTR` to cancel an active operation (returns `CKR_OPERATION_CANCEL_FAILED` if cancellation fails).

### 3.4 C_VerifySignature (Signature-First Verify Single-Part)

```c
CK_DECLARE_FUNCTION(CK_RV, C_VerifySignature)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_BYTE_PTR pData,                // Data to verify
  CK_ULONG ulDataLen                // Data length
);
```

- **Purpose**: Verifies a signature in a single-part operation. Must be preceded by `C_VerifySignatureInit`. Returns `CKR_OK` or `CKR_SIGNATURE_INVALID`.

### 3.5 C_VerifySignatureUpdate (Signature-First Verify Multi-Part)

```c
CK_DECLARE_FUNCTION(CK_RV, C_VerifySignatureUpdate)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_BYTE_PTR pPart,                // Data part to verify
  CK_ULONG ulPartLen                // Data part length
);
```

### 3.6 C_VerifySignatureFinal (Signature-First Verify Final)

```c
CK_DECLARE_FUNCTION(CK_RV, C_VerifySignatureFinal)(
  CK_SESSION_HANDLE hSession         // Session handle
);
```

- **Purpose**: Finishes a multi-part verification initialized with `C_VerifySignatureInit`. Returns `CKR_OK` or `CKR_SIGNATURE_INVALID`.

### 3.7 C_GetSessionValidationFlags

```c
CK_DECLARE_FUNCTION(CK_RV, C_GetSessionValidationFlags)(
  CK_SESSION_HANDLE hSession,                   // Session handle
  CK_SESSION_VALIDATION_FLAGS_TYPE type,        // Type of flags to query
  CK_FLAGS_PTR pFlags                           // Output: flags value
);
```

- **Purpose**: Fetches FIPS validation indicator flags from the session. Used for FIPS 140-3 validation indicator compliance (Section 4.15.3.1).

### 3.8 C_WrapKeyAuthenticated

```c
CK_DECLARE_FUNCTION(CK_RV, C_WrapKeyAuthenticated)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_MECHANISM_PTR pMechanism,       // Wrapping mechanism with message params
  CK_OBJECT_HANDLE hWrappingKey,     // Handle of wrapping key
  CK_OBJECT_HANDLE hKey,             // Handle of key to wrap
  CK_BYTE_PTR pAssociatedData,      // Associated data for AEAD mechanism
  CK_ULONG ulAssociatedDataLen,     // Associated data length
  CK_BYTE_PTR pWrappedKey,          // Output: wrapped key data
  CK_ULONG_PTR pulWrappedKeyLen     // Output: wrapped key length
);
```

- **Purpose**: Wraps a key using an AEAD authenticated mechanism (e.g., AES-GCM, AES-CCM). Supports provider-generated IVs/nonces via `CK_*_MESSAGE_PARAMS` structures. The primary use case is authenticated key wrapping with associated data.

### 3.9 C_UnwrapKeyAuthenticated

```c
CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKeyAuthenticated)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_MECHANISM_PTR pMechanism,       // Unwrapping mechanism with message params
  CK_OBJECT_HANDLE hUnwrappingKey,   // Handle of unwrapping key
  CK_BYTE_PTR pWrappedKey,          // Wrapped key data
  CK_ULONG ulWrappedKeyLen,         // Wrapped key data length
  CK_ATTRIBUTE_PTR pTemplate,       // Template for the resulting key
  CK_ULONG ulAttributeCount,        // Number of template attributes
  CK_BYTE_PTR pAssociatedData,      // Associated data for AEAD mechanism
  CK_ULONG ulAssociatedDataLen,     // Associated data length
  CK_OBJECT_HANDLE_PTR phKey        // Output: handle of unwrapped key
);
```

### 3.10 C_AsyncComplete

```c
CK_DECLARE_FUNCTION(CK_RV, C_AsyncComplete)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_UTF8CHAR_PTR pFunctionName,    // Name of async function to check
  CK_ASYNC_DATA_PTR pResult         // Output: operation result
);
```

- **Purpose**: Checks if an asynchronous operation (identified by function name) has completed, and if so, returns the result data. Returns `CKR_PENDING` if still in progress.

### 3.11 C_AsyncGetID

```c
CK_DECLARE_FUNCTION(CK_RV, C_AsyncGetID)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_UTF8CHAR_PTR pFunctionName,    // Name of async function
  CK_ULONG_PTR pulID                // Output: module-dependent identifier
);
```

- **Purpose**: Persists an async operation past `C_Finalize` by retrieving a module-dependent identifier. Allows reconnection after `C_Initialize` using `C_AsyncJoin`.

### 3.12 C_AsyncJoin

```c
CK_DECLARE_FUNCTION(CK_RV, C_AsyncJoin)(
  CK_SESSION_HANDLE hSession,        // Session handle
  CK_UTF8CHAR_PTR pFunctionName,    // Name of async function
  CK_ULONG ulID,                    // Identifier from C_AsyncGetID
  CK_BYTE_PTR pData,                // Reconnection data
  CK_ULONG ulData                   // Reconnection data length
);
```

- **Purpose**: Reconnects a client application to a previously-persisted asynchronous operation after reinitialization.

---

## 4. Modified Functions

### 4.1 C_OpenSession

- **New flag**: `CKF_ASYNC_SESSION` (`0x00000008`) can be set in the `flags` parameter to create an asynchronous session. Functions called on async sessions may return `CKR_PENDING`.
- **New error**: `CKR_SESSION_ASYNC_NOT_SUPPORTED` if the token does not support async sessions.

### 4.2 C_CloseSession / C_CloseAllSessions

- **New behavior**: Must handle cleanup of async sessions. If an async operation has an outstanding `C_AsyncGetID`, the client application should free memory passed into functions that returned `CKR_PENDING`.

### 4.3 C_GenerateRandom

- **New error**: `CKR_SEED_RANDOM_REQUIRED` - returned if the token requires `C_SeedRandom` to be called first (indicated by `CKF_SEED_RANDOM_REQUIRED` token flag).

### 4.4 C_DeriveKey

- **Extended**: Now also called by `C_EncapsulateKey` and `C_DecapsulateKey` indirectly (via KEM mechanisms that derive keys).
- **Key creation section** (Section 4.1) updated to list `C_EncapsulateKey` and `C_DecapsulateKey` as key-creating functions alongside `C_GenerateKey`, `C_GenerateKeyPair`, `C_UnwrapKey`, `C_DeriveKey`.

### 4.5 All Session-Based Functions

- **New error**: `CKR_PENDING` may be returned by most session-based functions when used on an asynchronous session, indicating the operation is still in progress.

### 4.6 C_VerifyInit

- **Clarification**: Now explicitly stated that any mechanism supporting `C_VerifyInit` MUST also support `C_VerifySignatureInit`.

---

## 5. New Mechanism Definitions

### 5.1 ML-KEM (FIPS 203 - Module-Lattice Key Encapsulation)

**Section 6.68**

- **Key type**: `CKK_ML_KEM`
- **Parameter set attribute**: `CKA_PARAMETER_SET` with values `CKP_ML_KEM_512`, `CKP_ML_KEM_768`, `CKP_ML_KEM_1024`
- **Key pair generation**: `CKM_ML_KEM_KEY_PAIR_GEN`
  - Parameters: mechanism parameter is NULL; parameter set specified via `CKA_PARAMETER_SET` in template
  - Generates `CKO_PUBLIC_KEY` with `CKA_ENCAPSULATE` and `CKO_PRIVATE_KEY` with `CKA_DECAPSULATE`
  - Contributes `CKA_KEY_TYPE`, `CKA_PARAMETER_SET`, `CKA_SEED`, `CKA_VALUE` to private key
- **Encapsulation/Decapsulation**: `CKM_ML_KEM`
  - Used with `C_EncapsulateKey` and `C_DecapsulateKey`
  - Mechanism parameter is NULL (set to NULL/0)
  - For `C_EncapsulateKey`: an ephemeral key is generated internally
  - Functions: Encapsulate, Decapsulate
- **Public key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE` (encapsulation key as byte array)
- **Private key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE`, `CKA_SEED` (at least one of `CKA_SEED` and `CKA_VALUE` must be present)

### 5.2 ML-DSA (FIPS 204 - Module-Lattice Digital Signatures)

**Section 6.67**

- **Key type**: `CKK_ML_DSA`
- **Parameter set attribute**: `CKA_PARAMETER_SET` with values `CKP_ML_DSA_44`, `CKP_ML_DSA_65`, `CKP_ML_DSA_87`
- **Key pair generation**: `CKM_ML_DSA_KEY_PAIR_GEN`
  - Parameter set specified via `CKA_PARAMETER_SET` in template
  - Contributes `CKA_KEY_TYPE`, `CKA_PARAMETER_SET`, `CKA_SEED`, `CKA_VALUE` to private key
- **Pure signing**: `CKM_ML_DSA`
  - Single-part operations only
  - Functions: Sign, Verify
- **Pre-hashed signing**: `CKM_HASH_ML_DSA`, `CKM_HASH_ML_DSA_SHA224` through `CKM_HASH_ML_DSA_SHAKE256`
  - `CKM_HASH_ML_DSA` supports multi-part operations
  - Hash-specific variants are single-part only
  - Functions: Sign, Verify
- **Public key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE` (verification key)
- **Private key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE`, `CKA_SEED` (at least one of `CKA_SEED` and `CKA_VALUE`)

### 5.3 SLH-DSA (FIPS 205 - Stateless Hash-Based Digital Signatures)

**Section 6.69**

- **Key type**: `CKK_SLH_DSA`
- **Parameter set attribute**: `CKA_PARAMETER_SET` with 12 parameter sets (`CKP_SLH_DSA_*`)
- **Key pair generation**: `CKM_SLH_DSA_KEY_PAIR_GEN`
  - Generates keys according to selected parameter set
- **Pure signing**: `CKM_SLH_DSA`
  - Single-part operations only
  - Functions: Sign, Verify
- **Pre-hashed signing**: `CKM_HASH_SLH_DSA`, `CKM_HASH_SLH_DSA_SHA224` through `CKM_HASH_SLH_DSA_SHAKE256`
  - `CKM_HASH_SLH_DSA` supports multi-part operations
  - Hash-specific variants are single-part only
  - Functions: Sign, Verify
- **Public key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE`
- **Private key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE`

### 5.4 HSS/LMS (Hash-Based Stateful Signatures)

**Section 6.65**

- **Key type**: `CKK_HSS`
- **Key pair generation**: `CKM_HSS_KEY_PAIR_GEN`
  - Configured by `CKA_HSS_LEVELS`, `CKA_HSS_LMS_TYPES`, `CKA_HSS_LMOTS_TYPES`
  - Contributes `CKA_HSS_LEVELS`, `CKA_HSS_LMS_TYPE`, `CKA_HSS_LMOTS_TYPE`, `CKA_VALUE`, `CKA_HSS_KEYS_REMAINING` to private key
- **Signing/Verification**: `CKM_HSS`
  - Single-part operations only
  - Functions: Sign, Verify
- **IMPORTANT**: Stateful scheme - signing consumes one-time signatures. `CKA_HSS_KEYS_REMAINING` decrements with each signature. Returns `CKR_KEY_EXHAUSTED` when no signatures remain.
- **Public key attributes**: `CKA_HSS_LEVELS`, `CKA_HSS_LMS_TYPE`, `CKA_HSS_LMOTS_TYPE`, `CKA_VALUE`
- **Private key attributes**: `CKA_HSS_LEVELS`, `CKA_HSS_LMS_TYPES`, `CKA_HSS_LMOTS_TYPES`, `CKA_VALUE`, `CKA_HSS_KEYS_REMAINING`

### 5.5 XMSS / XMSS^MT (Extended Merkle Signature Scheme)

**Section 6.66**

- **Key types**: `CKK_XMSS`, `CKK_XMSSMT`
- **Key pair generation**: `CKM_XMSS_KEY_PAIR_GEN`, `CKM_XMSSMT_KEY_PAIR_GEN`
  - Configured by `CKA_PARAMETER_SET` (uses numeric OID identifiers)
- **Signing/Verification**: `CKM_XMSS`, `CKM_XMSSMT`
  - Single-part operations only
  - Functions: Sign, Verify
- **IMPORTANT**: Also a stateful scheme like HSS.
- **Parameter set types**: `CK_XMSS_PARAMETER_SET_TYPE`, `CK_XMSSMT_PARAMETER_SET_TYPE` (both `typedef CK_ULONG`)
- **Public key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE`
- **Private key attributes**: `CKA_PARAMETER_SET`, `CKA_VALUE`

### 5.6 ECDH X AES KEY WRAP

**Section 6.3.22**

- **Mechanism**: `CKM_ECDH_X_AES_KEY_WRAP` (`0x00004038`)
- **Purpose**: ECDH Montgomery (X25519/X448) AES key wrapping. Replaces `CKM_ECDH_AES_KEY_WRAP` for `CKK_EC_MONTGOMERY` keys.
- **Key type**: Works with `CKK_EC_MONTGOMERY` keys
- **Functions**: Wrap, Unwrap
- **Uses**: Ephemeral Montgomery key + AES key wrap for secure key transport
- **Structure**: Uses `CK_ECDH_AES_KEY_WRAP_PARAMS` (same parameter structure as the deprecated mechanism)

### 5.7 ECDH COF AES KEY WRAP

- **Mechanism**: `CKM_ECDH_COF_AES_KEY_WRAP` (`0x00004039`)
- **Purpose**: ECDH cofactor AES key wrapping. Replacement for `CKM_ECDH_AES_KEY_WRAP` for `CKK_EC` keys.

### 5.8 PUB_KEY_FROM_PRIV_KEY

**Section 6.7** (referenced)

- **Mechanism**: `CKM_PUB_KEY_FROM_PRIV_KEY` (`0x0000403A`)
- **Purpose**: Derives a public key object from an existing private key. Supported for XMSS, XMSS^MT, ML-KEM, ML-DSA, and SLH-DSA key types.
- **Functions**: Derive (via `C_DeriveKey`)

---

## 6. New Attributes

### 6.1 Attributes for Public Key Objects

| Attribute | Type | Default | Description |
|---|---|---|---|
| `CKA_ENCAPSULATE` | `CK_BBOOL` | Implementation-dependent | Whether the key can be used for KEM encapsulation |

### 6.2 Attributes for Private Key Objects

| Attribute | Type | Default | Description |
|---|---|---|---|
| `CKA_DECAPSULATE` | `CK_BBOOL` | Implementation-dependent | Whether the key can be used for KEM decapsulation |

### 6.3 Attributes for Key Objects (General)

| Attribute | Type | Description |
|---|---|---|
| `CKA_PARAMETER_SET` | Algorithm-specific `CK_ULONG` | Identifies the parameter set for PQC keys |
| `CKA_SEED` | `Byte array` | Seed for deterministic PQC key generation |
| `CKA_OBJECT_VALIDATION_FLAGS` | `CK_FLAGS` | FIPS validation state flags for the object |

### 6.4 Attributes for HSS Key Objects

| Attribute | Type | Applies To | Description |
|---|---|---|---|
| `CKA_HSS_LEVELS` | `CK_ULONG` | Public, Private | Number of HSS levels (1-8) |
| `CKA_HSS_LMS_TYPE` | `CK_ULONG` | Public | LMS type (single-level) |
| `CKA_HSS_LMOTS_TYPE` | `CK_ULONG` | Public | LMOTS type (single-level) |
| `CKA_HSS_LMS_TYPES` | `Byte array` | Private | Array of LMS types per level |
| `CKA_HSS_LMOTS_TYPES` | `Byte array` | Private | Array of LMOTS types per level |
| `CKA_HSS_KEYS_REMAINING` | `CK_ULONG` | Private | Remaining one-time signatures |

---

## 7. Version and Interface Changes

### 7.1 CK_FUNCTION_LIST_3_2

- **New structure**: `CK_FUNCTION_LIST_3_2` extends the function list with 11 new function pointers (see Section 2.1).
- **Version field**: Must be `{3, 2}` or higher.
- **Pointer types**: `CK_FUNCTION_LIST_3_2_PTR`, `CK_FUNCTION_LIST_3_2_PTR_PTR`.

### 7.2 C_GetInterface Behavior

- When called with version `{3, 2}`, returns a `CK_FUNCTION_LIST_3_2` pointer via the interface.
- The `CK_INTERFACE.flags` field can now include `CKF_INTERFACE_FORK_SAFE` to indicate the interface is safe for use after `fork()`.

### 7.3 Mechanisms vs. Functions Table

- **New column**: "Encapsulate & Decapsulate" added to the main Mechanisms vs. Functions table (Table 36) alongside the existing Encrypt/Decrypt, Sign/Verify, etc. columns.

### 7.4 Session Validation Flags

- Sessions now carry validation flags queryable via `C_GetSessionValidationFlags`.
- `CKA_OBJECT_VALIDATION_FLAGS` can only be set by the token in ways consistent with the validation policy.
- Objects must have appropriate flags set for operations to proceed in validated mode.

### 7.5 Asynchronous Session Support

- New session type: asynchronous sessions created with `CKF_ASYNC_SESSION` flag.
- Token advertises support via `CKF_ASYNC_SESSION_SUPPORTED` in `CK_TOKEN_INFO`.
- Functions may return `CKR_PENDING` on async sessions.
- Three new functions (`C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`) manage async operation lifecycle.

---

## 8. Deprecations

### 8.1 CKM_ECDH_AES_KEY_WRAP (Deprecated)

- **Status**: Deprecated in PKCS#11 v3.2.
- **Replacement**: Use `CKM_ECDH_COF_AES_KEY_WRAP` for `CKK_EC` keys and `CKM_ECDH_X_AES_KEY_WRAP` for `CKK_EC_MONTGOMERY` keys.
- **Migration**: `CKM_ECDH_X_AES_KEY_WRAP` works identically to the deprecated mechanism when applied to Montgomery keys.

### 8.2 CKT_TRUSTED_DELEGATOR (Renamed)

- **Renamed to**: `CKT_TRUST_ANCHOR` (per WD09 revision).

### 8.3 CKK_ECDSA (Previously Deprecated)

- Remains deprecated since v3.0. Use `CKK_EC` instead.

---

## 9. New Object Types

### 9.1 Validation Objects (CKO_VALIDATION)

**Section 4.15**

- **Object class**: `CKO_VALIDATION` (`0x0000000A`)
- **Purpose**: Represent cryptographic module validation information (e.g., FIPS 140-2/140-3 certifications).
- **Attributes**: `CKA_VALIDATION_TYPE`, `CKA_VALIDATION_VERSION`, `CKA_VALIDATION_LEVEL`, `CKA_VALIDATION_MODULE_ID`, `CKA_VALIDATION_FLAG`, `CKA_VALIDATION_AUTHORITY_TYPE`, `CKA_VALIDATION_COUNTRY`, `CKA_VALIDATION_CERTIFICATE_IDENTIFIER`, `CKA_VALIDATION_CERTIFICATE_URI`, `CKA_VALIDATION_VENDOR_URI`, `CKA_VALIDATION_PROFILE`.
- **Validation indicators** (Section 4.15.3): Sessions carry validation flags queryable with `C_GetSessionValidationFlags`. Key objects carry `CKA_OBJECT_VALIDATION_FLAGS`.

### 9.2 Trust Objects (CKO_TRUST)

**Section 4.7**

- **Object class**: `CKO_TRUST` (`0x0000000B`)
- **Purpose**: Represent trust policy decisions for certificates. Allow applications to query whether a certificate is trusted for specific purposes.
- **Attributes**: `CKA_TRUST_SERVER_AUTH`, `CKA_TRUST_CLIENT_AUTH`, `CKA_TRUST_CODE_SIGNING`, `CKA_TRUST_EMAIL_PROTECTION`, `CKA_TRUST_IPSEC_IKE`, `CKA_TRUST_TIME_STAMPING`, `CKA_TRUST_OCSP_SIGNING`.

### 9.3 Mechanism Objects (CKO_MECHANISM) (Clarified)

- **Object class**: `CKO_MECHANISM` (`0x00000007`)
- **Purpose**: Represent mechanisms as queryable objects with `CKA_MECHANISM_TYPE` attribute. Introduced in v3.0, further refined in v3.1/v3.2.

### 9.4 Profile Objects (CKO_PROFILE) (Clarified)

- Expanded documentation for profile objects and their usage patterns.

---

## 10. Post-Quantum Cryptography Details

### 10.1 Key Wrapping for PQC Keys

- ML-KEM private keys and SLH-DSA private keys can be wrapped using standard wrapping mechanisms.
- For ML-KEM and ML-DSA keys, private keys can be encoded with a PKCS#8-like format for wrapping.

### 10.2 Deterministic Key Generation

- ML-DSA and ML-KEM support deterministic key generation via `CKA_SEED`.
- At least one of `CKA_SEED` and `CKA_VALUE` must be present for ML-DSA and ML-KEM private keys.
- If `CKA_SEED` is provided during key pair generation, the generated keys are deterministically derived from the seed.

### 10.3 Stateful Signature Schemes

- HSS/LMS and XMSS/XMSS^MT are **stateful** signature schemes.
- Each signing operation consumes a one-time signature key.
- `CKA_HSS_KEYS_REMAINING` tracks remaining signatures.
- `CKR_KEY_EXHAUSTED` is returned when no signatures remain.
- Tokens MUST ensure state is persisted to prevent signature reuse.
- `CKF_SEED_RANDOM_REQUIRED` and `CKR_SEED_RANDOM_REQUIRED` support tokens that need RNG seeding.

### 10.4 KEM vs. Key Agreement

- The new KEM functions (`C_EncapsulateKey`/`C_DecapsulateKey`) are distinct from `C_DeriveKey`.
- KEM produces a random shared secret + ciphertext (encapsulation), rather than computing a shared secret from two key shares (key agreement).
- EC-based KEMs (ECDH as KEM) can also use `C_EncapsulateKey`/`C_DecapsulateKey` with `CKM_ECDH`.
- The Mechanisms vs. Functions table has a new column for Encapsulate/Decapsulate support.

---

## Summary of Changes by Version

### Changes in v3.1 (baseline for v3.2)

- `C_LoginUser` function
- `C_SessionCancel` function
- Message-based encryption/decryption functions (MessageEncrypt*, MessageDecrypt*)
- Message-based sign/verify functions (MessageSign*, MessageVerify*)
- `CKF_FIND_OBJECTS`, `CKF_MULTI_MESSAGE`, `CKF_INTERFACE_FORK_SAFE` flags
- `CK_INTERFACE` structure and `C_GetInterfaceList`/`C_GetInterface` functions
- Profile objects (`CKO_PROFILE`)
- Mechanism objects (`CKO_MECHANISM`)

### Changes NEW in v3.2

- **KEM operations**: `C_EncapsulateKey`, `C_DecapsulateKey` (and `CKA_ENCAPSULATE`, `CKA_DECAPSULATE`, `CKF_ENCAPSULATE`, `CKF_DECAPSULATE`)
- **Signature-first verify**: `C_VerifySignatureInit`, `C_VerifySignature`, `C_VerifySignatureUpdate`, `C_VerifySignatureFinal`
- **Authenticated key wrapping**: `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`
- **Asynchronous operations**: `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`, `CK_ASYNC_DATA`, `CKF_ASYNC_SESSION`, `CKF_ASYNC_SESSION_SUPPORTED`, `CKR_PENDING`, `CKR_SESSION_ASYNC_NOT_SUPPORTED`
- **Validation objects**: `CKO_VALIDATION`, `CKA_VALIDATION_*`, `CKA_OBJECT_VALIDATION_FLAGS`, `C_GetSessionValidationFlags`, `CKR_OPERATION_NOT_VALIDATED`
- **Trust objects**: `CKO_TRUST`, `CKA_TRUST_*`
- **Post-quantum cryptography**: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), HSS/LMS, XMSS/XMSS^MT
- **All new PQC key types, mechanisms, parameter sets, and attributes** listed above
- **`CKM_PUB_KEY_FROM_PRIV_KEY`**: Derive public key from private key
- **`CKM_ECDH_X_AES_KEY_WRAP`**, **`CKM_ECDH_COF_AES_KEY_WRAP`**: Replace deprecated `CKM_ECDH_AES_KEY_WRAP`
- **New error codes**: `CKR_AEAD_DECRYPT_FAILED`, `CKR_OPERATION_CANCEL_FAILED`, `CKR_KEY_EXHAUSTED`, `CKR_SEED_RANDOM_REQUIRED`, `CKR_PARAMETER_SET_NOT_SUPPORTED`
- **`CK_FUNCTION_LIST_3_2`**: New function list structure incorporating all new functions
- **`CKF_SEED_RANDOM_REQUIRED`**: Token flag
