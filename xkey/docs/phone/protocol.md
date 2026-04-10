# Bidirectional JSON-RPC 2.0 Protocol

## Overview

The xkey-phone protocol uses JSON-RPC 2.0 over Noise XX encrypted channels. Methods are namespaced by direction:

- `local.*` -- Laptop requests operations on the phone's Android Keystore
- `remote.*` -- Phone requests operations on the laptop's xkmsd backends
- (no prefix) -- Existing FIDO2-specific methods (backward compatible)

Both directions share the same encrypted Noise channel.

## Protocol Basics

| Property | Value |
|----------|-------|
| Version | JSON-RPC 2.0 |
| Encoding | JSON over binary (Noise encrypted) |
| Transport | BLE GATT or TCP (ADB/USB) |
| Fragmentation | For messages exceeding BLE MTU (247 bytes) |
| Request IDs | Atomic uint64 counter, unique per session |
| Max message size | 65519 bytes (Noise limit) |

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "local.sign",
  "params": {
    "keyId": "my-signing-key",
    "algorithm": "ES256",
    "data": "base64-encoded-data"
  }
}
```

### Response Format (Success)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "signature": "base64-encoded-signature"
  }
}
```

### Response Format (Error)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "key not found",
    "data": "no key with ID 'my-signing-key'"
  }
}
```

---

## `local.*` Methods (Laptop to Phone)

These methods are sent by the laptop and executed on the phone's Android Keystore (TEE/StrongBox).

| Method | Description |
|--------|-------------|
| `local.generateKey` | Generate a key pair in Android Keystore |
| `local.sign` | Sign data with a phone key |
| `local.decrypt` | Decrypt data with a phone key |
| `local.symmetricEncrypt` | Encrypt data with a symmetric key |
| `local.symmetricDecrypt` | Decrypt data with a symmetric key |
| `local.hmac` | Compute HMAC with a phone key |
| `local.ecdh` | ECDH key agreement |
| `local.getPublicKey` | Retrieve a key's public component |
| `local.listKeys` | List keys stored on the phone |
| `local.getKeyInfo` | Get metadata for a specific key |
| `local.deleteKey` | Delete a key from the phone |
| `local.setKeyPolicy` | Set access policy for a key |
| `local.attestKey` | Get Android Key Attestation for a key |
| `local.getCapabilities` | Query phone capabilities and algorithms |
| `local.listFido2Credentials` | Discover shared FIDO2 credentials |
| `local.signFido2Assertion` | Sign a FIDO2 assertion with a shared credential |

### local.generateKey

Generate a new key pair in Android Keystore.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Unique key identifier |
| `algorithm` | string | yes | Key algorithm: `ES256`, `ES384`, `ES512`, `RSA2048`, `RSA4096` |
| `purpose` | []string | yes | Key purposes: `sign`, `decrypt`, `agree` |
| `requireBiometric` | bool | no | Require biometric for each use (default: true) |
| `strongBox` | bool | no | Require StrongBox backing (default: true) |
| `attestation` | bool | no | Generate with attestation (default: false) |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | Key identifier |
| `publicKey` | string | Base64-encoded public key (DER/SPKI) |
| `algorithm` | string | Key algorithm |
| `hardwareBacked` | bool | True if key is hardware-backed |
| `securityLevel` | string | `strongbox`, `tee`, or `software` |

**Errors:** `-32010` KeyAlreadyExists, `-32011` UnsupportedAlgorithm, `-32012` StorageFull, `-32013` StrongBoxUnavailable

### local.sign

Sign data with a key stored on the phone. Triggers biometric prompt if key requires it.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Signing algorithm: `ES256`, `ES384`, `ES512`, `RS256`, `PS256` |
| `data` | string | yes | Base64-encoded data to sign |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `signature` | string | Base64-encoded signature (DER for ECDSA, PKCS#1 for RSA) |

**Errors:** `-32000` KeyNotFound, `-32001` UserCancelled, `-32002` BiometricFailed, `-32005` OperationTimeout

### local.decrypt

Decrypt data with a key stored on the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Decryption algorithm: `RSA-OAEP-256`, `RSA-OAEP-384` |
| `ciphertext` | string | yes | Base64-encoded ciphertext |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `plaintext` | string | Base64-encoded decrypted data |

**Errors:** `-32000` KeyNotFound, `-32001` UserCancelled, `-32014` DecryptionFailed

### local.symmetricEncrypt

Encrypt data with a symmetric key on the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Symmetric key identifier |
| `algorithm` | string | yes | `AES-256-GCM` |
| `plaintext` | string | yes | Base64-encoded plaintext |
| `aad` | string | no | Base64-encoded additional authenticated data |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `ciphertext` | string | Base64-encoded ciphertext |
| `nonce` | string | Base64-encoded nonce/IV |
| `tag` | string | Base64-encoded authentication tag |

### local.symmetricDecrypt

Decrypt data with a symmetric key on the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Symmetric key identifier |
| `algorithm` | string | yes | `AES-256-GCM` |
| `ciphertext` | string | yes | Base64-encoded ciphertext |
| `nonce` | string | yes | Base64-encoded nonce/IV |
| `tag` | string | yes | Base64-encoded authentication tag |
| `aad` | string | no | Base64-encoded additional authenticated data |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `plaintext` | string | Base64-encoded plaintext |

### local.hmac

Compute HMAC with a key on the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | HMAC key identifier |
| `algorithm` | string | yes | `HMAC-SHA256`, `HMAC-SHA384`, `HMAC-SHA512` |
| `data` | string | yes | Base64-encoded data |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | Base64-encoded HMAC value |

### local.ecdh

Perform ECDH key agreement using a phone key and a peer public key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Local ECDH key identifier |
| `peerPublicKey` | string | yes | Base64-encoded peer public key (DER/SPKI) |
| `kdf` | string | no | Key derivation: `HKDF-SHA256` (default), `HKDF-SHA384` |
| `kdfInfo` | string | no | Base64-encoded HKDF info parameter |
| `keyLength` | int | no | Derived key length in bytes (default: 32) |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `derivedKey` | string | Base64-encoded derived key material |

### local.getPublicKey

Retrieve the public key component of a stored key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `publicKey` | string | Base64-encoded public key (DER/SPKI) |
| `algorithm` | string | Key algorithm |

### local.listKeys

List all keys stored on the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `filter` | string | no | Filter by purpose: `sign`, `decrypt`, `agree`, `all` (default) |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `keys` | []KeyInfo | Array of key metadata objects |

KeyInfo fields:

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | Key identifier |
| `algorithm` | string | Key algorithm |
| `purpose` | []string | Key purposes |
| `securityLevel` | string | `strongbox`, `tee`, or `software` |
| `requiresBiometric` | bool | Whether biometric is required |
| `createdAt` | string | ISO 8601 creation timestamp |

### local.getKeyInfo

Get detailed metadata for a specific key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |

**Response result:**

Same as KeyInfo above, plus:

| Field | Type | Description |
|-------|------|-------------|
| `attestation` | object | Attestation data if key was created with attestation |

### local.deleteKey

Delete a key from the phone's keystore.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `deleted` | bool | True if key was deleted |

### local.setKeyPolicy

Set or update access policy for a key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `requireBiometric` | bool | no | Require biometric for each use |
| `allowedOrigins` | []string | no | Allowed relying party origins |
| `maxUsesPerAuth` | int | no | Max operations per biometric auth (0 = unlimited) |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `updated` | bool | True if policy was updated |

### local.attestKey

Request Android Key Attestation for a key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `challenge` | string | yes | Base64-encoded attestation challenge (nonce) |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `certificateChain` | []string | Array of Base64-encoded X.509 certificates (leaf first) |
| `securityLevel` | string | `strongbox`, `tee`, or `software` |
| `attestationVersion` | int | Android Key Attestation schema version |

### local.getCapabilities

Query phone capabilities and supported algorithms.

**Request params:** None

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `deviceName` | string | Phone model name |
| `androidVersion` | int | Android API level |
| `strongBox` | bool | StrongBox available |
| `supportedAlgorithms` | []string | Supported signing algorithms |
| `supportedKdf` | []string | Supported KDF algorithms |
| `maxCredentials` | int | Maximum credential count |
| `currentCredentials` | int | Current credential count |
| `biometricTypes` | []string | `fingerprint`, `face`, `iris` |

### local.listFido2Credentials

Discover FIDO2 credentials shared by the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rpId` | string | no | Filter by relying party ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `credentials` | []Fido2Credential | Array of shared credentials |

Fido2Credential fields:

| Field | Type | Description |
|-------|------|-------------|
| `credentialId` | string | Base64-encoded credential ID |
| `rpId` | string | Relying party ID |
| `rpName` | string | Relying party display name |
| `userName` | string | User name |
| `userDisplayName` | string | User display name |
| `algorithm` | int | COSE algorithm identifier |
| `createdAt` | string | ISO 8601 creation timestamp |
| `signCount` | int | Current signature counter |

### local.signFido2Assertion

Sign a FIDO2 assertion using a shared credential on the phone.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credentialId` | string | yes | Base64-encoded credential ID |
| `clientDataHash` | string | yes | Base64-encoded client data hash |
| `rpId` | string | yes | Relying party ID |
| `flags` | int | no | Authenticator data flags (default: 0x05 = UP+UV) |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `authenticatorData` | string | Base64-encoded authenticator data |
| `signature` | string | Base64-encoded assertion signature |
| `signCount` | int | Updated signature counter |

---

## `remote.*` Methods (Phone to Laptop)

These methods are sent by the phone and executed on the laptop's xkmsd backends.

| Method | Description |
|--------|-------------|
| `remote.listBackends` | List available xkmsd backends |
| `remote.listKeys` | List keys in a xkmsd backend |
| `remote.getPublicKey` | Get public key from xkmsd |
| `remote.sign` | Sign data with a xkmsd key |
| `remote.verify` | Verify a signature using xkmsd |
| `remote.encrypt` | Encrypt data with a xkmsd key |
| `remote.decrypt` | Decrypt data with a xkmsd key |
| `remote.deriveKey` | ECDH/HKDF key derivation via xkmsd |
| `remote.generateKey` | Generate a key on a xkmsd backend |
| `remote.getKeyInfo` | Get key metadata from xkmsd |
| `remote.attestKey` | Get attestation from xkmsd backend |

### remote.listBackends

List available xkmsd backends that the phone is allowed to access.

**Request params:** None

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `backends` | []BackendInfo | Array of available backends |

BackendInfo fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Backend identifier |
| `type` | string | Backend type: `tpm2`, `pkcs11`, `software`, `awskms`, `gcpkms`, `azurekv` |
| `hardwareBacked` | bool | Whether backend uses hardware |
| `capabilities` | []string | `sign`, `decrypt`, `agree`, `attest` |

### remote.listKeys

List keys in a xkmsd backend.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `backend` | string | no | Backend ID (default: all allowed backends) |
| `filter` | string | no | Filter by key type |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `keys` | []RemoteKeyInfo | Array of key metadata |

RemoteKeyInfo fields:

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | Key identifier |
| `backend` | string | Backend that stores the key |
| `algorithm` | string | Key algorithm |
| `hardwareBacked` | bool | Whether key is hardware-backed |

### remote.getPublicKey

Get the public key from a xkmsd key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `publicKey` | string | Base64-encoded public key (DER/SPKI) |
| `algorithm` | string | Key algorithm |

### remote.sign

Sign data with a key in xkmsd.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Signing algorithm |
| `data` | string | yes | Base64-encoded data to sign |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `signature` | string | Base64-encoded signature |

### remote.verify

Verify a signature using xkmsd.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Signing algorithm |
| `data` | string | yes | Base64-encoded original data |
| `signature` | string | yes | Base64-encoded signature to verify |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `valid` | bool | True if signature is valid |

### remote.encrypt

Encrypt data with a xkmsd key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Encryption algorithm |
| `plaintext` | string | yes | Base64-encoded plaintext |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `ciphertext` | string | Base64-encoded ciphertext |

### remote.decrypt

Decrypt data with a xkmsd key.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Decryption algorithm |
| `ciphertext` | string | yes | Base64-encoded ciphertext |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `plaintext` | string | Base64-encoded plaintext |

### remote.deriveKey

Perform ECDH key agreement and KDF via xkmsd.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Local ECDH key identifier |
| `peerPublicKey` | string | yes | Base64-encoded peer public key (DER/SPKI) |
| `kdf` | string | no | `HKDF-SHA256` (default), `HKDF-SHA384` |
| `kdfInfo` | string | no | Base64-encoded HKDF info |
| `keyLength` | int | no | Derived key length in bytes (default: 32) |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `derivedKey` | string | Base64-encoded derived key material |

### remote.generateKey

Generate a new key on a xkmsd backend.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `algorithm` | string | yes | Key algorithm |
| `backend` | string | yes | Target backend ID |
| `purpose` | []string | yes | Key purposes: `sign`, `decrypt`, `agree` |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | Key identifier |
| `publicKey` | string | Base64-encoded public key (DER/SPKI) |
| `algorithm` | string | Key algorithm |
| `backend` | string | Backend that stores the key |

### remote.getKeyInfo

Get key metadata from xkmsd.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | Key identifier |
| `backend` | string | Backend storing the key |
| `algorithm` | string | Key algorithm |
| `hardwareBacked` | bool | Whether key uses hardware |
| `createdAt` | string | ISO 8601 creation timestamp |

### remote.attestKey

Get attestation for a xkmsd key from its backend.

**Request params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyId` | string | yes | Key identifier |
| `challenge` | string | yes | Base64-encoded attestation nonce |
| `backend` | string | no | Backend ID |

**Response result:**

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Attestation format: `tpm2`, `pkcs11`, `none` |
| `attestation` | string | Base64-encoded attestation data |
| `certificateChain` | []string | Base64-encoded X.509 certificate chain |

**Errors:** `-32020` AttestationUnsupported (software backend)

---

## Existing Methods (No Namespace Prefix)

These are the original FIDO2-specific methods, retained for backward compatibility.

| Method | Description |
|--------|-------------|
| `ping` | Health check / keepalive |
| `generateKey` | Generate FIDO2 credential key pair |
| `sign` | Sign data with FIDO2 credential |
| `deleteKey` | Delete FIDO2 credential |
| `loadKey` | Load/verify FIDO2 credential exists |
| `getInfo` | Device information and capabilities |

These methods are documented in the [BLE Protocol Specification](../ble/protocol.md).

---

## Error Code Registry

### Standard JSON-RPC Errors

| Code | Name | Description |
|------|------|-------------|
| -32700 | ParseError | Invalid JSON received |
| -32600 | InvalidRequest | Invalid JSON-RPC request structure |
| -32601 | MethodNotFound | Method does not exist |
| -32602 | InvalidParams | Invalid method parameters |
| -32603 | InternalError | Internal server error |

### FIDO2 Application Errors (Existing)

| Code | Name | Description |
|------|------|-------------|
| -32000 | KeyNotFound | Credential or key not found |
| -32001 | UserCancelled | User dismissed biometric or prompt |
| -32002 | BiometricFailed | Biometric verification failed |
| -32003 | UnsupportedAlgorithm | Algorithm not supported by device |
| -32004 | InvalidCredentialID | Malformed credential identifier |
| -32005 | OperationTimeout | Operation timed out waiting |
| -32006 | StorageFull | No space for new credentials or keys |
| -32007 | KeyExists | Key with this ID already exists |

### General Key Operation Errors

| Code | Name | Description |
|------|------|-------------|
| -32010 | KeyAlreadyExists | Key ID already in use |
| -32011 | UnsupportedOperation | Operation not supported by key or backend |
| -32012 | PolicyViolation | Key policy prevents this operation |
| -32013 | StrongBoxUnavailable | StrongBox requested but not available |
| -32014 | DecryptionFailed | Ciphertext could not be decrypted |
| -32015 | VerificationFailed | Signature or MAC verification failed |
| -32016 | InvalidKeyPurpose | Key not authorized for this operation |

### Remote Backend Errors

| Code | Name | Description |
|------|------|-------------|
| -32020 | AttestationUnsupported | Backend does not support attestation |
| -32021 | BackendNotFound | Specified backend does not exist |
| -32022 | BackendDenied | Sharing policy denies access to backend |
| -32023 | BackendUnavailable | Backend temporarily unavailable |
| -32024 | XkmsdUnavailable | xkmsd service not reachable |

---

## Message Flow Examples

### Example 1: Generate Key on Phone and Sign Data

```
Laptop                                    Phone
  |                                         |
  |-- local.generateKey ------------------>|
  |   {keyId:"sig-key", algorithm:"ES256", |
  |    purpose:["sign"]}                   |
  |                                         | Generate key in StrongBox
  |<-- result: {publicKey:"...",  ---------|
  |     securityLevel:"strongbox"}         |
  |                                         |
  |-- local.sign ------------------------->|
  |   {keyId:"sig-key",                    |
  |    algorithm:"ES256",                  |
  |    data:"base64-hash"}                 |
  |                                         | Show biometric prompt
  |                                         | User authenticates
  |<-- result: {signature:"..."} ----------|
  |                                         |
```

### Example 2: Phone Signs with Laptop's TPM2 Backend

```
Laptop                                    Phone
  |                                         |
  |<-- remote.listBackends ----------------|
  |                                         |
  |-- result: [{id:"tpm2",  ------------->|
  |     type:"tpm2", ...}]                 |
  |                                         |
  |<-- remote.sign ------------------------|
  |   {keyId:"tpm-sign-key",              |
  |    algorithm:"ES256",                  |
  |    data:"base64-hash",                |
  |    backend:"tpm2"}                     |
  |                                         |
  |   [laptop calls xkmsd SDK:         |
  |    client.Sign("tpm-sign-key",...)]    |
  |                                         |
  |-- result: {signature:"..."} --------->|
  |                                         |
```

### Example 3: Bidirectional Attestation

```
Laptop                                    Phone
  |                                         |
  |-- local.attestKey -------------------->|
  |   {keyId:"sig-key",                    |
  |    challenge:"base64-nonce"}           |
  |                                         | Android Key Attestation
  |<-- result: {certificateChain:[...],  --|
  |     securityLevel:"strongbox"}         |
  |                                         |
  | [Laptop verifies chain to Google root] |
  |                                         |
  |<-- remote.attestKey -------------------|
  |   {keyId:"tpm-key",                    |
  |    challenge:"base64-nonce"}           |
  |                                         |
  | [Laptop calls xkmsd attestation]   |
  |                                         |
  |-- result: {format:"tpm2",  ---------->|
  |     attestation:"...",                  |
  |     certificateChain:[...]}            |
  |                                         |
  | [Phone verifies TPM2 attestation]      |
  |                                         |
```

---

## See Also

- [BLE Protocol Specification](../ble/protocol.md) - Existing FIDO2 protocol details
- [Attestation](attestation.md) - Detailed attestation flows
- [Bidirectional Key Sharing](bidirectional.md) - Sharing design and policies
- [Transport](transport.md) - BLE and USB transport details
