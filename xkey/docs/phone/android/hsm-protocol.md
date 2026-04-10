# HSM Protocol Handler (local.* Methods)

## Overview

The Android app handles `local.*` JSON-RPC requests from the laptop. These requests arrive over the Noise-encrypted BLE or TCP channel and are dispatched to the Android Keystore via `KeystoreManager`. The phone effectively operates as a remote HSM for the laptop.

## Handler Architecture

```
BLE GATT / TCP Server
        |
        v
  Noise Decryption
        |
        v
  JSON-RPC Parser
        |
        v
  Method Dispatcher (map-based, O(1) lookup)
        |
        +-- local.generateKey     -> KeystoreManager.generateKeyForAlgorithm()
        +-- local.sign            -> KeystoreManager.signWithAlgorithm()
        +-- local.decrypt         -> KeystoreManager.decrypt()
        +-- local.symmetricEncrypt -> KeystoreManager.symmetricEncrypt()
        +-- local.symmetricDecrypt -> KeystoreManager.symmetricDecrypt()
        +-- local.hmac            -> KeystoreManager.computeHMAC()
        +-- local.ecdh            -> KeystoreManager.performECDH()
        +-- local.getPublicKey    -> KeystoreManager.getPublicKeyXxx()
        +-- local.listKeys        -> KeyDao.getByType() / observeAll()
        +-- local.getKeyInfo      -> KeyDao.getByKeyId() + KeystoreManager.getKeyInfo()
        +-- local.deleteKey       -> KeystoreManager.deleteKey() + KeyDao.deleteByKeyId()
        +-- local.setKeyPolicy    -> KeyDao.update()
        +-- local.attestKey       -> KeystoreManager.getKeyAttestation()
        +-- local.getCapabilities -> Runtime capability detection
```

## Method Reference

### local.generateKey

Generate a new key in Android Keystore.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "local.generateKey",
  "params": {
    "keyId": "my-signing-key",
    "algorithm": "ES256",
    "keyType": "signing",
    "label": "Code Signing Key",
    "strongBox": true,
    "biometricRequired": true,
    "authDurationSeconds": 5,
    "attestationChallenge": "base64-encoded-nonce"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "keyId": "my-signing-key",
    "publicKeyDer": "base64-encoded-der",
    "strongBoxBacked": true,
    "attestationChain": ["base64-cert-leaf", "base64-cert-intermediate", "base64-cert-root"]
  }
}
```

### local.sign

Sign data with a stored key. Requires biometric authentication.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "local.sign",
  "params": {
    "keyId": "my-signing-key",
    "algorithm": "ES256",
    "data": "base64-encoded-data"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "signature": "base64-encoded-der-signature"
  }
}
```

### local.decrypt

RSA OAEP decryption. Requires biometric authentication.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "local.decrypt",
  "params": {
    "keyId": "my-rsa-key",
    "ciphertext": "base64-encoded-ciphertext"
  }
}
```

### local.symmetricEncrypt / local.symmetricDecrypt

AES-GCM encryption and decryption. Optional AAD parameter.

**Encrypt request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "local.symmetricEncrypt",
  "params": {
    "keyId": "my-aes-key",
    "plaintext": "base64-encoded-plaintext",
    "aad": "base64-encoded-aad"
  }
}
```

**Encrypt response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "ciphertext": "base64-encoded-iv-ciphertext-tag"
  }
}
```

### local.hmac

Compute HMAC over data.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "local.hmac",
  "params": {
    "keyId": "my-hmac-key",
    "data": "base64-encoded-data"
  }
}
```

### local.ecdh

ECDH key agreement. Returns the raw shared secret.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "local.ecdh",
  "params": {
    "keyId": "my-ec-key",
    "peerPublicKey": "base64-encoded-der-public-key"
  }
}
```

### local.getPublicKey

Export a public key in the requested format.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "local.getPublicKey",
  "params": {
    "keyId": "my-signing-key",
    "format": "der"
  }
}
```

**Format values:** `der`, `pem`, `ssh`, `cose`

### local.listKeys

List keys, optionally filtered by type.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "local.listKeys",
  "params": {
    "keyType": "signing"
  }
}
```

### local.getKeyInfo

Get metadata for a specific key, combining Room data and Android Keystore info.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "local.getKeyInfo",
  "params": {
    "keyId": "my-signing-key"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "result": {
    "keyId": "my-signing-key",
    "keyType": "signing",
    "algorithm": "ES256",
    "keySizeBits": 256,
    "strongBoxBacked": true,
    "biometricRequired": true,
    "useCount": 42,
    "createdAt": 1706140800,
    "lastUsedAt": 1706227200
  }
}
```

### local.deleteKey

Delete a key from both Android Keystore and Room.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "local.deleteKey",
  "params": {
    "keyId": "my-signing-key"
  }
}
```

### local.setKeyPolicy

Update key policy fields (label, shareable, biometric requirement).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "local.setKeyPolicy",
  "params": {
    "keyId": "my-signing-key",
    "shareable": true,
    "label": "Updated Label"
  }
}
```

### local.attestKey

Get Android Key Attestation certificate chain for a key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "local.attestKey",
  "params": {
    "keyId": "my-signing-key",
    "challenge": "base64-encoded-nonce"
  }
}
```

### local.getCapabilities

Runtime detection of device capabilities.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 13,
  "result": {
    "strongBox": true,
    "biometric": true,
    "algorithms": ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "AES-128-GCM", "AES-256-GCM", "HMAC-SHA256", "HMAC-SHA512"],
    "strongBoxAlgorithms": ["ES256", "AES-256-GCM", "HMAC-SHA256"],
    "attestationSupported": true,
    "ecdhSupported": true
  }
}
```

## Biometric Flow

For operations that use a key (sign, decrypt, encrypt, hmac, ecdh):

```
1. JSON-RPC request received and parsed
2. Handler resolves keyId to Android Keystore alias
3. BiometricPrompt displayed to user
4. User authenticates (fingerprint or face)
5. Android Keystore unlocks key for configured auth duration
6. Cryptographic operation performed
7. Result serialized as JSON-RPC response
8. Response encrypted via Noise and sent back
```

If the key was generated with `authDurationSeconds > 0`, subsequent operations within that window skip the biometric prompt. If `authDurationSeconds = 0`, biometric is required for every operation.

## Key Metadata Sync

After each operation, the handler updates Room:

| Field | Update |
|-------|--------|
| `use_count` | Incremented by 1 |
| `last_used_at` | Set to current timestamp |
| `sign_count` | Incremented by 1 (FIDO2 keys only) |

## Error Mapping

Android Keystore exceptions are mapped to JSON-RPC error codes.

| Android Exception | JSON-RPC Code | Message |
|-------------------|---------------|---------|
| `KeyPermanentlyInvalidatedException` | -32000 | Key invalidated (biometric enrollment changed or key deleted) |
| `KeyNotFoundException` | -32000 | Key not found in Keystore |
| `UserNotAuthenticatedException` | -32002 | Biometric authentication required but not completed |
| `BiometricPromptCancelled` | -32001 | User cancelled biometric prompt |
| `StrongBoxUnavailableException` | -32004 | Algorithm not supported in StrongBox |
| `UnsupportedAlgorithmException` | -32003 | Algorithm not supported on this device |
| `IllegalBlockSizeException` | -32603 | Ciphertext size invalid for decryption |
| `AEADBadTagException` | -32603 | AES-GCM authentication tag verification failed |
