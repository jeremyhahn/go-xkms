# C API Reference

The libkeychain.so library provides a C-callable API for the embedded backend.

## Header File

```c
// keychain.h
#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
```

## Initialization

### keychain_init

Initialize the keychain library.

```c
int keychain_init(const char* config_path);
```

**Parameters:**
- `config_path`: Path to configuration file, or NULL for defaults

**Returns:**
- `0` on success
- Non-zero error code on failure

**Example:**
```c
if (keychain_init("/etc/gokeychain/config.yaml") != 0) {
    fprintf(stderr, "Failed to initialize: %s\n",
            keychain_error_string(keychain_last_error()));
    exit(1);
}
```

### keychain_cleanup

Clean up and release all resources.

```c
void keychain_cleanup(void);
```

**Notes:**
- Must be called before process exit
- Invalidates all key handles

## Key Generation

### keychain_generate_rsa

Generate an RSA key pair.

```c
int keychain_generate_rsa(const char* key_id, int bits, void** handle);
```

**Parameters:**
- `key_id`: Unique identifier for the key
- `bits`: Key size (2048, 3072, 4096)
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success
- `KEYCHAIN_ERR_INVALID_KEY_SIZE` if bits is invalid
- `KEYCHAIN_ERR_KEY_EXISTS` if key_id already exists

**Example:**
```c
void* handle = NULL;
if (keychain_generate_rsa("my-rsa-key", 2048, &handle) == 0) {
    printf("Generated RSA key\n");
}
```

### keychain_generate_ecdsa

Generate an ECDSA key pair.

```c
int keychain_generate_ecdsa(const char* key_id, const char* curve, void** handle);
```

**Parameters:**
- `key_id`: Unique identifier for the key
- `curve`: Curve name ("P-256", "P-384", "P-521", "secp256k1")
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success
- `KEYCHAIN_ERR_INVALID_CURVE` if curve is unsupported

**Example:**
```c
void* handle = NULL;
if (keychain_generate_ecdsa("my-ec-key", "P-256", &handle) == 0) {
    printf("Generated ECDSA key\n");
}
```

### keychain_generate_ed25519

Generate an Ed25519 key pair.

```c
int keychain_generate_ed25519(const char* key_id, void** handle);
```

**Parameters:**
- `key_id`: Unique identifier for the key
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success

## Key Operations

### keychain_get_key

Retrieve an existing key.

```c
int keychain_get_key(const char* key_id, void** handle);
```

**Parameters:**
- `key_id`: Key identifier
- `handle`: Output pointer to key handle

**Returns:**
- `0` on success
- `KEYCHAIN_ERR_NOT_FOUND` if key does not exist

### keychain_delete_key

Delete a key.

```c
int keychain_delete_key(const char* key_id);
```

**Parameters:**
- `key_id`: Key identifier

**Returns:**
- `0` on success
- `KEYCHAIN_ERR_NOT_FOUND` if key does not exist

### keychain_list_keys

List all key identifiers.

```c
int keychain_list_keys(char*** key_ids, int* count);
```

**Parameters:**
- `key_ids`: Output pointer to array of key IDs
- `count`: Output pointer to array length

**Returns:**
- `0` on success

**Notes:**
- Caller must free with `keychain_free_key_list()`

### keychain_free_key_list

Free key list returned by `keychain_list_keys()`.

```c
void keychain_free_key_list(char** key_ids, int count);
```

## Signing Operations

### keychain_sign

Sign data using a private key.

```c
int keychain_sign(void* handle, const uint8_t* data, size_t data_len,
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
- `KEYCHAIN_ERR_INVALID_HANDLE` if handle is invalid

**Notes:**
- Caller must free signature with `keychain_free_signature()`
- Hash algorithm is determined by key type

**Example:**
```c
uint8_t* sig = NULL;
size_t sig_len = 0;
if (keychain_sign(handle, data, data_len, &sig, &sig_len) == 0) {
    // Use signature
    keychain_free_signature(sig);
}
```

### keychain_free_signature

Free signature returned by `keychain_sign()`.

```c
void keychain_free_signature(uint8_t* signature);
```

## Verification

### keychain_verify

Verify a signature.

```c
int keychain_verify(void* handle, const uint8_t* data, size_t data_len,
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
- `KEYCHAIN_ERR_VERIFY_FAILED` if invalid

## Public Key Export

### keychain_get_public_key

Export the public key in DER format.

```c
int keychain_get_public_key(void* handle, uint8_t** pubkey, size_t* len);
```

**Parameters:**
- `handle`: Key handle
- `pubkey`: Output pointer to DER-encoded public key
- `len`: Output pointer to length

**Returns:**
- `0` on success

**Notes:**
- Caller must free with `keychain_free_public_key()`

### keychain_free_public_key

Free public key returned by `keychain_get_public_key()`.

```c
void keychain_free_public_key(uint8_t* pubkey);
```

## Random Number Generation

### keychain_generate_random

Generate cryptographically secure random bytes.

```c
int keychain_generate_random(uint8_t* buffer, size_t len);
```

**Parameters:**
- `buffer`: Output buffer
- `len`: Number of bytes to generate

**Returns:**
- `0` on success

## Error Handling

### keychain_error_string

Get human-readable error message.

```c
const char* keychain_error_string(int error_code);
```

**Parameters:**
- `error_code`: Error code from any function

**Returns:**
- Static string describing the error

### keychain_last_error

Get the last error code.

```c
int keychain_last_error(void);
```

**Returns:**
- Last error code set by any function

## Error Codes

```c
#define KEYCHAIN_OK                     0
#define KEYCHAIN_ERR_INIT_FAILED        1
#define KEYCHAIN_ERR_NOT_INITIALIZED    2
#define KEYCHAIN_ERR_INVALID_HANDLE     3
#define KEYCHAIN_ERR_NOT_FOUND          4
#define KEYCHAIN_ERR_KEY_EXISTS         5
#define KEYCHAIN_ERR_INVALID_KEY_SIZE   6
#define KEYCHAIN_ERR_INVALID_CURVE      7
#define KEYCHAIN_ERR_SIGN_FAILED        8
#define KEYCHAIN_ERR_VERIFY_FAILED      9
#define KEYCHAIN_ERR_MEMORY             10
#define KEYCHAIN_ERR_CONFIG             11
#define KEYCHAIN_ERR_IO                 12
#define KEYCHAIN_ERR_AUTH               13
```

## Thread Safety

All functions are thread-safe when:
- `keychain_init()` is called once before any other calls
- `keychain_cleanup()` is called once after all other calls complete

## Complete Example

```c
#include <stdio.h>
#include <string.h>
#include "keychain.h"

int main() {
    // Initialize
    if (keychain_init(NULL) != 0) {
        fprintf(stderr, "Init failed: %s\n",
                keychain_error_string(keychain_last_error()));
        return 1;
    }

    // Generate key
    void* handle = NULL;
    if (keychain_generate_ecdsa("test-key", "P-256", &handle) != 0) {
        fprintf(stderr, "Keygen failed: %s\n",
                keychain_error_string(keychain_last_error()));
        keychain_cleanup();
        return 1;
    }

    // Sign data
    const char* message = "Hello, World!";
    uint8_t* sig = NULL;
    size_t sig_len = 0;

    if (keychain_sign(handle, (uint8_t*)message, strlen(message),
                      &sig, &sig_len) != 0) {
        fprintf(stderr, "Sign failed: %s\n",
                keychain_error_string(keychain_last_error()));
        keychain_cleanup();
        return 1;
    }

    printf("Signature length: %zu\n", sig_len);

    // Verify
    if (keychain_verify(handle, (uint8_t*)message, strlen(message),
                        sig, sig_len) == 0) {
        printf("Signature valid!\n");
    } else {
        printf("Signature invalid!\n");
    }

    // Cleanup
    keychain_free_signature(sig);
    keychain_delete_key("test-key");
    keychain_cleanup();

    return 0;
}
```

## Compiling

```bash
# Compile example
gcc -o example example.c -L/usr/lib -lkeychain

# Run
./example
```

## Header Footer

```c
#ifdef __cplusplus
}
#endif

#endif // KEYCHAIN_H
```
