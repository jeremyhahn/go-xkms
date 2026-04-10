# C API Reference

The libxkms.so library provides a C-callable API for the embedded backend.

## Header File

```c
// xkms.h
#ifndef XKMS_H
#define XKMS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
```

## Initialization

### xkms_init

Initialize the xkms library.

```c
int xkms_init(const char* config_path);
```

**Parameters:**
- `config_path`: Path to configuration file, or NULL for defaults

**Returns:**
- `0` on success
- Non-zero error code on failure

**Example:**
```c
if (xkms_init("/etc/goxkms/config.yaml") != 0) {
    fprintf(stderr, "Failed to initialize: %s\n",
            xkms_error_string(xkms_last_error()));
    exit(1);
}
```

### xkms_cleanup

Clean up and release all resources.

```c
void xkms_cleanup(void);
```

**Notes:**
- Must be called before process exit
- Invalidates all key handles

## Key Generation

### xkms_generate_rsa

Generate an RSA key pair.

```c
int xkms_generate_rsa(const char* key_id, int bits, void** handle);
```

**Parameters:**
- `key_id`: Unique identifier for the key
- `bits`: Key size (2048, 3072, 4096)
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success
- `XKMS_ERR_INVALID_KEY_SIZE` if bits is invalid
- `XKMS_ERR_KEY_EXISTS` if key_id already exists

**Example:**
```c
void* handle = NULL;
if (xkms_generate_rsa("my-rsa-key", 2048, &handle) == 0) {
    printf("Generated RSA key\n");
}
```

### xkms_generate_ecdsa

Generate an ECDSA key pair.

```c
int xkms_generate_ecdsa(const char* key_id, const char* curve, void** handle);
```

**Parameters:**
- `key_id`: Unique identifier for the key
- `curve`: Curve name ("P-256", "P-384", "P-521", "secp256k1")
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success
- `XKMS_ERR_INVALID_CURVE` if curve is unsupported

**Example:**
```c
void* handle = NULL;
if (xkms_generate_ecdsa("my-ec-key", "P-256", &handle) == 0) {
    printf("Generated ECDSA key\n");
}
```

### xkms_generate_ed25519

Generate an Ed25519 key pair.

```c
int xkms_generate_ed25519(const char* key_id, void** handle);
```

**Parameters:**
- `key_id`: Unique identifier for the key
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success

## Key Operations

### xkms_get_key

Retrieve an existing key.

```c
int xkms_get_key(const char* key_id, void** handle);
```

**Parameters:**
- `key_id`: Key identifier
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success
- `XKMS_ERR_NOT_FOUND` if key does not exist

### xkms_delete_key

Delete a key.

```c
int xkms_delete_key(const char* key_id);
```

**Parameters:**
- `key_id`: Key identifier

**Returns:**
- `0` on success
- `XKMS_ERR_NOT_FOUND` if key does not exist

### xkms_list_keys

List all key identifiers.

```c
int xkms_list_keys(char*** key_ids, int* count);
```

**Parameters:**
- `key_ids`: Output pointer to array of key IDs
- `count`: Output pointer to array length

**Returns:**
- `0` on success

**Notes:**
- Caller must free with `xkms_free_key_list()`

### xkms_free_key_list

Free key list returned by `xkms_list_keys()`.

```c
void xkms_free_key_list(char** key_ids, int count);
```

## Signing Operations

### xkms_sign

Sign data using a private key.

```c
int xkms_sign(void* handle, const uint8_t* data, size_t data_len,
                  uint8_t** signature, size_t* sig_len);
```

**Parameters:**
- `handle`: Key handle from generate or get
- `data`: Data to sign
- `data_len`: Length of data
- `signature`: Output pointer to signature
- `sig_len`: Output pointer to signature length

**Returns:**
- `0` on success
- `XKMS_ERR_INVALID_HANDLE` if handle is invalid

**Notes:**
- Caller must free signature with `xkms_free_signature()`
- Hash algorithm is determined by key type

**Example:**
```c
uint8_t* sig = NULL;
size_t sig_len = 0;
if (xkms_sign(handle, data, data_len, &sig, &sig_len) == 0) {
    // Use signature
    xkms_free_signature(sig);
}
```

### xkms_free_signature

Free signature returned by `xkms_sign()`.

```c
void xkms_free_signature(uint8_t* signature);
```

## Verification

### xkms_verify

Verify a signature.

```c
int xkms_verify(void* handle, const uint8_t* data, size_t data_len,
                    const uint8_t* signature, size_t sig_len);
```

**Parameters:**
- `handle`: Key handle (public or private)
- `data`: Original data
- `data_len`: Length of data
- `signature`: Signature to verify
- `sig_len`: Length of signature

**Returns:**
- `0` if signature is valid
- `XKMS_ERR_VERIFY_FAILED` if invalid

## Public Key Export

### xkms_get_public_key

Export the public key in DER format.

```c
int xkms_get_public_key(void* handle, uint8_t** pubkey, size_t* len);
```

**Parameters:**
- `handle`: Key handle
- `pubkey`: Output pointer to DER-encoded public key
- `len`: Output pointer to length

**Returns:**
- `0` on success

**Notes:**
- Caller must free with `xkms_free_public_key()`

### xkms_free_public_key

Free public key returned by `xkms_get_public_key()`.

```c
void xkms_free_public_key(uint8_t* pubkey);
```

## Random Number Generation

### xkms_generate_random

Generate cryptographically secure random bytes.

```c
int xkms_generate_random(uint8_t* buffer, size_t len);
```

**Parameters:**
- `buffer`: Output buffer
- `len`: Number of bytes to generate

**Returns:**
- `0` on success

## Error Handling

### xkms_error_string

Get human-readable error message.

```c
const char* xkms_error_string(int error_code);
```

**Parameters:**
- `error_code`: Error code from any function

**Returns:**
- Static string describing the error

### xkms_last_error

Get the last error code.

```c
int xkms_last_error(void);
```

**Returns:**
- Last error code set by any function

## Error Codes

```c
#define XKMS_OK                     0
#define XKMS_ERR_INIT_FAILED        1
#define XKMS_ERR_NOT_INITIALIZED    2
#define XKMS_ERR_INVALID_HANDLE     3
#define XKMS_ERR_NOT_FOUND          4
#define XKMS_ERR_KEY_EXISTS         5
#define XKMS_ERR_INVALID_KEY_SIZE   6
#define XKMS_ERR_INVALID_CURVE      7
#define XKMS_ERR_SIGN_FAILED        8
#define XKMS_ERR_VERIFY_FAILED      9
#define XKMS_ERR_MEMORY             10
#define XKMS_ERR_CONFIG             11
#define XKMS_ERR_IO                 12
#define XKMS_ERR_AUTH               13
```

## Thread Safety

All functions are thread-safe when:
- `xkms_init()` is called once before any other calls
- `xkms_cleanup()` is called once after all other calls complete

## Complete Example

```c
#include <stdio.h>
#include <string.h>
#include "xkms.h"

int main() {
    // Initialize
    if (xkms_init(NULL) != 0) {
        fprintf(stderr, "Init failed: %s\n",
                xkms_error_string(xkms_last_error()));
        return 1;
    }

    // Generate key
    void* handle = NULL;
    if (xkms_generate_ecdsa("test-key", "P-256", &handle) != 0) {
        fprintf(stderr, "Keygen failed: %s\n",
                xkms_error_string(xkms_last_error()));
        xkms_cleanup();
        return 1;
    }

    // Sign data
    const char* message = "Hello, World!";
    uint8_t* sig = NULL;
    size_t sig_len = 0;

    if (xkms_sign(handle, (uint8_t*)message, strlen(message),
                      &sig, &sig_len) != 0) {
        fprintf(stderr, "Sign failed: %s\n",
                xkms_error_string(xkms_last_error()));
        xkms_cleanup();
        return 1;
    }

    printf("Signature length: %zu\n", sig_len);

    // Verify
    if (xkms_verify(handle, (uint8_t*)message, strlen(message),
                        sig, sig_len) == 0) {
        printf("Signature valid!\n");
    } else {
        printf("Signature invalid!\n");
    }

    // Cleanup
    xkms_free_signature(sig);
    xkms_delete_key("test-key");
    xkms_cleanup();

    return 0;
}
```

## Compiling

```bash
# Compile example
gcc -o example example.c -L/usr/lib -lxkms

# Run
./example
```

---

## PKCS#11 v3.2 Go API Reference

The following functions were added in the v3.2 upgrade. All are methods on `*Module` in `pkg/pkcs11/module/`. All v3.2 functions perform input validation (session existence, mechanism presence, key handle validity) before returning `CKR_FUNCTION_NOT_SUPPORTED` pending hardware backend integration.

### KEM Operations

#### EncapsulateKey

Create a shared secret and ciphertext from a public key using a KEM mechanism.

```go
func (m *Module) EncapsulateKey(sessionHandle SessionHandle, mechanism *Mechanism, publicKeyHandle ObjectHandle, template []Attribute) (ObjectHandle, []byte, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `mechanism` - KEM mechanism (must support CKF_ENCAPSULATE)
- `publicKeyHandle` - Recipient's public key handle
- `template` - Attributes for the created shared secret key

**Returns:** shared secret key handle, KEM ciphertext, error

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending KEM-capable backend integration.

#### DecapsulateKey

Recover a shared secret from KEM ciphertext using a private key. Per the OASIS spec, the template precedes the ciphertext in the parameter list.

```go
func (m *Module) DecapsulateKey(sessionHandle SessionHandle, mechanism *Mechanism, privateKeyHandle ObjectHandle, template []Attribute, ciphertext []byte) (ObjectHandle, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `mechanism` - KEM mechanism (must match encapsulation mechanism)
- `privateKeyHandle` - Decapsulator's private key handle
- `template` - Attributes for the recovered shared secret key (precedes ciphertext per spec)
- `ciphertext` - KEM ciphertext received from the encapsulator

**Returns:** shared secret key handle, error

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending KEM-capable backend integration.

### Authenticated Key Wrapping

#### WrapKeyAuthenticated

Wrap a key using an AEAD mechanism with optional associated data (AAD). The authentication tag is integrated into the returned ciphertext.

```go
func (m *Module) WrapKeyAuthenticated(sessionHandle SessionHandle, mechanism *Mechanism, wrappingKeyHandle ObjectHandle, keyHandle ObjectHandle, associatedData []byte) ([]byte, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `mechanism` - Wrapping mechanism (must support AEAD authenticated wrapping)
- `wrappingKeyHandle` - Key used for wrapping
- `keyHandle` - Key to be wrapped
- `associatedData` - Optional additional authenticated data (AAD); may be nil

**Returns:** wrapped key material (ciphertext with integrated auth tag), error

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending backend integration.

#### UnwrapKeyAuthenticated

Unwrap a key by decrypting AEAD-wrapped key material and verifying the integrated authentication tag. The associated data must match what was provided during wrapping.

```go
func (m *Module) UnwrapKeyAuthenticated(sessionHandle SessionHandle, mechanism *Mechanism, unwrappingKeyHandle ObjectHandle, wrappedKey []byte, template []Attribute, associatedData []byte) (ObjectHandle, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `mechanism` - Unwrapping mechanism (must match wrapping mechanism)
- `unwrappingKeyHandle` - Key used for unwrapping
- `wrappedKey` - Wrapped key material (ciphertext with integrated auth tag)
- `template` - Attributes for the unwrapped key object
- `associatedData` - Optional AAD; must match the AAD used during wrapping

**Returns:** unwrapped key handle, error

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending backend integration.

### Signature-First Verification

Signature-first verification provides the signature before data, enabling streaming verification for PQC algorithms where the signature initializes the verification state machine.

#### VerifySignatureInit

Initialize a signature-first verification operation.

```go
func (m *Module) VerifySignatureInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle, signature []byte) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `mechanism` - Verification mechanism
- `keyHandle` - Public key handle
- `signature` - Signature to verify against

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### VerifySignature

Perform single-part signature-first verification. Must follow `VerifySignatureInit`.

```go
func (m *Module) VerifySignature(sessionHandle SessionHandle, data []byte) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `data` - Data to verify the signature against

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### VerifySignatureUpdate

Feed data to a multi-part signature-first verification. Must follow `VerifySignatureInit`.

```go
func (m *Module) VerifySignatureUpdate(sessionHandle SessionHandle, part []byte) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `part` - Data chunk to feed into verification

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### VerifySignatureFinal

Complete a multi-part signature-first verification and return the result.

```go
func (m *Module) VerifySignatureFinal(sessionHandle SessionHandle) error
```

**Parameters:**
- `sessionHandle` - Active session handle

**Returns:** nil if signature is valid, `PKCS11Error` otherwise.

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### MessageVerifySignatureInit

Initialize a message-based signature-first verification session.

```go
func (m *Module) MessageVerifySignatureInit(sessionHandle SessionHandle, mechanism *Mechanism, keyHandle ObjectHandle) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `mechanism` - Verification mechanism
- `keyHandle` - Public key handle

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### VerifyMessageSignature

Verify a complete message with signature-first ordering.

```go
func (m *Module) VerifyMessageSignature(sessionHandle SessionHandle, parameter []byte, data []byte, signature []byte) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `parameter` - Mechanism-specific parameter
- `data` - Complete message data
- `signature` - Signature to verify

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### VerifyMessageSignatureBegin

Start streaming message signature-first verification. The signature is provided upfront.

```go
func (m *Module) VerifyMessageSignatureBegin(sessionHandle SessionHandle, parameter []byte, signature []byte) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `parameter` - Mechanism-specific parameter
- `signature` - Signature to verify against

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### VerifyMessageSignatureNext

Feed a chunk of data to streaming message signature-first verification.

```go
func (m *Module) VerifyMessageSignatureNext(sessionHandle SessionHandle, parameter []byte, data []byte, isLast bool) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `parameter` - Mechanism-specific parameter
- `data` - Message data chunk
- `isLast` - True if this is the final chunk

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

#### MessageVerifySignatureFinal

Finalize a message-based signature-first verification session.

```go
func (m *Module) MessageVerifySignatureFinal(sessionHandle SessionHandle) error
```

**Parameters:**
- `sessionHandle` - Active session handle

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending PQC backend integration.

### Async Operations

Async operations are identified by function name (string), not by numeric operation ID. This allows applications to query and manage specific async functions by their PKCS#11 name (e.g., "C_Sign").

#### AsyncComplete

Retrieve the result of a completed asynchronous operation identified by function name.

```go
func (m *Module) AsyncComplete(sessionHandle SessionHandle, functionName string) ([]byte, ObjectHandle, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `functionName` - Name of the async function to complete (e.g., "C_Sign")

**Returns:** result data, result object handle (InvalidHandle if not applicable), error

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending backend integration.

#### AsyncGetID

Retrieve the operation ID for an asynchronous operation identified by function name.

```go
func (m *Module) AsyncGetID(sessionHandle SessionHandle, functionName string) (uint64, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `functionName` - Name of the async function to query (e.g., "C_Sign")

**Returns:** operation ID, error

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending backend integration.

#### AsyncJoin

Block until an async operation completes, identified by function name and operation ID.

```go
func (m *Module) AsyncJoin(sessionHandle SessionHandle, functionName string, id uint64, data []byte) error
```

**Parameters:**
- `sessionHandle` - Active session handle
- `functionName` - Name of the async function to join (e.g., "C_Sign")
- `id` - Operation identifier obtained from AsyncGetID
- `data` - Optional data to pass to the join operation; may be nil

**Status:** Returns `CKR_FUNCTION_NOT_SUPPORTED` pending backend integration.

### Validation Framework

#### GetSessionValidationFlags

Query the validation status flags for a session. The flagsType parameter selects which category of validation flags to query (CK_SESSION_VALIDATION_FLAGS_TYPE). Used for FIPS 140-3 and Common Criteria certification.

```go
func (m *Module) GetSessionValidationFlags(sessionHandle SessionHandle, flagsType uint64) (uint64, error)
```

**Parameters:**
- `sessionHandle` - Active session handle
- `flagsType` - Category of validation flags to query (CK_SESSION_VALIDATION_FLAGS_TYPE)

**Returns:** bitmask of validation flags, error. Currently returns `0` (no validation). Will return `CKF_VALIDATION_PROTECTED` when operating in a FIPS-certified configuration.

### v3.2 Constants

All values below are from the OASIS PKCS#11 v3.2 CSD01 pkcs11t.h header.

#### Mechanism Flags

| Constant | Value | Description |
|----------|-------|-------------|
| `CKF_FIND_OBJECTS` | `0x00000040` | Mechanism can be used with C_FindObjects |
| `CKF_ENCAPSULATE` | `0x10000000` | Mechanism supports C_EncapsulateKey |
| `CKF_DECAPSULATE` | `0x20000000` | Mechanism supports C_DecapsulateKey |

#### Session/Token Flags

| Constant | Value | Description |
|----------|-------|-------------|
| `CKF_ASYNC_SESSION` | `0x00000008` | Session supports asynchronous operations |
| `CKF_ASYNC_SESSION_SUPPORTED` | `0x04000000` | Token supports asynchronous sessions |
| `CKF_SEED_RANDOM_REQUIRED` | `0x02000000` | Token requires application to seed RNG |

#### Validation Flags

| Constant | Value | Description |
|----------|-------|-------------|
| `CKF_VALIDATION_PROTECTED` | `0x00000001` | Module in validated (FIPS) configuration |

#### Return Values (v3.2 additions)

| Constant | Value | Description |
|----------|-------|-------------|
| `CKR_PENDING` | `0x00000204` | Asynchronous operation is pending completion |
| `CKR_SESSION_ASYNC_NOT_SUPPORTED` | `0x00000205` | Session does not support async operations |
| `CKR_SEED_RANDOM_REQUIRED` | `0x00000206` | Token requires RNG seeding before use |
| `CKR_OPERATION_NOT_VALIDATED` | `0x00000207` | Operation not validated per token policy |
| `CKR_PARAMETER_SET_NOT_SUPPORTED` | `0x00000209` | Requested parameter set not supported |

#### Object Classes

| Constant | Value | Description |
|----------|-------|-------------|
| `CKO_VALIDATION` | `0x0000000A` | Validation object |
| `CKO_TRUST` | `0x0000000B` | Trust object |

#### Key Types (PQC)

| Constant | Value | Description |
|----------|-------|-------------|
| `CKK_HSS` | `0x00000046` | HSS/LMS (RFC 8554) |
| `CKK_XMSS` | `0x00000047` | XMSS (RFC 8391) |
| `CKK_XMSSMT` | `0x00000048` | XMSS^MT (RFC 8391) |
| `CKK_ML_KEM` | `0x00000049` | ML-KEM (FIPS 203) |
| `CKK_ML_DSA` | `0x0000004A` | ML-DSA (FIPS 204) |
| `CKK_SLH_DSA` | `0x0000004B` | SLH-DSA (FIPS 205) |

#### Attributes (PQC)

| Constant | Value | Description |
|----------|-------|-------------|
| `CKA_PARAMETER_SET` | `0x0000061D` | PQC parameter set identifier |
| `CKA_ENCAPSULATE` | `0x00000633` | Key supports encapsulation |
| `CKA_DECAPSULATE` | `0x00000634` | Key supports decapsulation |
| `CKA_SEED` | `0x00000637` | Seed for deterministic key generation |

#### PQC Mechanism Types (39 mechanisms)

**ML-KEM (FIPS 203):**

| Constant | Value |
|----------|-------|
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0000000F` |
| `CKM_ML_KEM` | `0x00000017` |

**ML-DSA (FIPS 204):**

| Constant | Value |
|----------|-------|
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x0000001C` |
| `CKM_ML_DSA` | `0x0000001D` |
| `CKM_HASH_ML_DSA` | `0x0000001F` |
| `CKM_HASH_ML_DSA_SHA224` | `0x00000023` |
| `CKM_HASH_ML_DSA_SHA256` | `0x00000024` |
| `CKM_HASH_ML_DSA_SHA384` | `0x00000025` |
| `CKM_HASH_ML_DSA_SHA512` | `0x00000026` |
| `CKM_HASH_ML_DSA_SHA3_224` | `0x00000027` |
| `CKM_HASH_ML_DSA_SHA3_256` | `0x00000028` |
| `CKM_HASH_ML_DSA_SHA3_384` | `0x00000029` |
| `CKM_HASH_ML_DSA_SHA3_512` | `0x0000002A` |
| `CKM_HASH_ML_DSA_SHAKE128` | `0x0000002B` |
| `CKM_HASH_ML_DSA_SHAKE256` | `0x0000002C` |

**SLH-DSA (FIPS 205):**

| Constant | Value |
|----------|-------|
| `CKM_SLH_DSA_KEY_PAIR_GEN` | `0x0000002D` |
| `CKM_SLH_DSA` | `0x0000002E` |
| `CKM_HASH_SLH_DSA` | `0x00000034` |
| `CKM_HASH_SLH_DSA_SHA224` | `0x00000036` |
| `CKM_HASH_SLH_DSA_SHA256` | `0x00000037` |
| `CKM_HASH_SLH_DSA_SHA384` | `0x00000038` |
| `CKM_HASH_SLH_DSA_SHA512` | `0x00000039` |
| `CKM_HASH_SLH_DSA_SHA3_224` | `0x0000003A` |
| `CKM_HASH_SLH_DSA_SHA3_256` | `0x0000003B` |
| `CKM_HASH_SLH_DSA_SHA3_384` | `0x0000003C` |
| `CKM_HASH_SLH_DSA_SHA3_512` | `0x0000003D` |
| `CKM_HASH_SLH_DSA_SHAKE128` | `0x0000003E` |
| `CKM_HASH_SLH_DSA_SHAKE256` | `0x0000003F` |

**TLS 1.2 Extended Master Key:**

| Constant | Value |
|----------|-------|
| `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE` | `0x00000056` |
| `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH` | `0x00000057` |

**HSS/LMS (RFC 8554):**

| Constant | Value |
|----------|-------|
| `CKM_HSS_KEY_PAIR_GEN` | `0x00004032` |
| `CKM_HSS` | `0x00004033` |

**XMSS/XMSS^MT (RFC 8391):**

| Constant | Value |
|----------|-------|
| `CKM_XMSS_KEY_PAIR_GEN` | `0x00004034` |
| `CKM_XMSSMT_KEY_PAIR_GEN` | `0x00004035` |
| `CKM_XMSS` | `0x00004036` |
| `CKM_XMSSMT` | `0x00004037` |

**ECDH Key Wrap and Utility:**

| Constant | Value |
|----------|-------|
| `CKM_ECDH_X_AES_KEY_WRAP` | `0x00004038` |
| `CKM_ECDH_COF_AES_KEY_WRAP` | `0x00004039` |
| `CKM_PUB_KEY_FROM_PRIV_KEY` | `0x0000403A` |

## Header Footer

```c
#ifdef __cplusplus
}
#endif

#endif // XKMS_H
```
