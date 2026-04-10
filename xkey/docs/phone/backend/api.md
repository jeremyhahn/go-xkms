# Phone Backend API Reference

## Overview

The phone backend uses JSON-RPC 2.0 over Noise XX encrypted channels. Methods in the `local.*` namespace are sent from the laptop to the phone, requesting operations on the phone's Android Keystore.

## Method Summary

| Method | Description | Returns |
|--------|-------------|---------|
| `local.generateKey` | Generate key with specified algorithm | Public key |
| `local.sign` | Sign data with key | Signature bytes |
| `local.decrypt` | RSA decryption | Plaintext bytes |
| `local.symmetricEncrypt` | AES-GCM encryption | Ciphertext + nonce |
| `local.symmetricDecrypt` | AES-GCM decryption | Plaintext bytes |
| `local.hmac` | HMAC computation | MAC bytes |
| `local.ecdh` | ECDH key agreement | Shared secret bytes |
| `local.getPublicKey` | Export public key | Key in requested format |
| `local.listKeys` | List keys by type | Key metadata array |
| `local.getKeyInfo` | Detailed key metadata | Key info object |
| `local.deleteKey` | Delete key from phone | Success boolean |
| `local.setKeyPolicy` | Update key sharing/auth policies | Updated policy |
| `local.attestKey` | Android Key Attestation | X.509 cert chain |
| `local.getCapabilities` | Phone capabilities | Capabilities object |
| `ping` | Connection health check | Pong |
| `getInfo` | Device information | Device info |

## Key Generation

### `local.generateKey`

Generate a new key on the phone's Android Keystore.

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
    "label": "My Signing Key",
    "biometricRequired": true,
    "authDurationSeconds": 5,
    "strongBox": true,
    "shareable": false
  }
}
```

**Supported algorithms:** `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`, `RSA2048`, `RSA3072`, `RSA4096`, `AES128`, `AES256`, `HMAC-SHA256`, `HMAC-SHA512`

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "keyId": "my-signing-key",
    "publicKeyDer": "<base64>",
    "algorithm": "ES256",
    "keySizeBits": 256,
    "strongBoxBacked": true
  }
}
```

## Signing

### `local.sign`

Sign data with a key on the phone.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "local.sign",
  "params": {
    "keyId": "my-signing-key",
    "data": "<base64 data hash>",
    "algorithm": "ES256"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "signature": "<base64 DER-encoded signature>"
  }
}
```

## Decryption

### `local.decrypt`

RSA decryption (OAEP or PKCS1v15).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "local.decrypt",
  "params": {
    "keyId": "my-rsa-key",
    "ciphertext": "<base64>",
    "padding": "oaep",
    "hash": "sha256"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "plaintext": "<base64>"
  }
}
```

## Symmetric Encryption

### `local.symmetricEncrypt`

AES-GCM encryption.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "local.symmetricEncrypt",
  "params": {
    "keyId": "my-aes-key",
    "plaintext": "<base64>",
    "aad": "<base64 optional>"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "ciphertext": "<base64>",
    "nonce": "<base64 12-byte IV>"
  }
}
```

### `local.symmetricDecrypt`

AES-GCM decryption.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "local.symmetricDecrypt",
  "params": {
    "keyId": "my-aes-key",
    "ciphertext": "<base64>",
    "nonce": "<base64>",
    "aad": "<base64 optional>"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "plaintext": "<base64>"
  }
}
```

## HMAC

### `local.hmac`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "local.hmac",
  "params": {
    "keyId": "my-hmac-key",
    "data": "<base64>"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "mac": "<base64>"
  }
}
```

## ECDH Key Agreement

### `local.ecdh`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "local.ecdh",
  "params": {
    "keyId": "my-ec-key",
    "peerPublicKey": "<base64 DER-encoded peer public key>"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "sharedSecret": "<base64>"
  }
}
```

## Public Key Export

### `local.getPublicKey`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "local.getPublicKey",
  "params": {
    "keyId": "my-signing-key",
    "format": "der"
  }
}
```

**Supported formats:** `der`, `pem`, `ssh`, `cose`

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "result": {
    "publicKey": "<base64 key in requested format>",
    "format": "der",
    "algorithm": "ES256"
  }
}
```

## Key Management

### `local.listKeys`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "local.listKeys",
  "params": {
    "keyType": "signing",
    "algorithm": "ES256"
  }
}
```

Both params are optional filters.

### `local.getKeyInfo`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "local.getKeyInfo",
  "params": {
    "keyId": "my-signing-key"
  }
}
```

### `local.deleteKey`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "local.deleteKey",
  "params": {
    "keyId": "my-signing-key"
  }
}
```

### `local.setKeyPolicy`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "local.setKeyPolicy",
  "params": {
    "keyId": "my-signing-key",
    "shareable": true,
    "biometricRequired": true,
    "authDurationSeconds": 10
  }
}
```

## Attestation

### `local.attestKey`

Brief reference -- see [attestation.md](attestation.md) for full details.

### `local.getCapabilities`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 14,
  "method": "local.getCapabilities",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 14,
  "result": {
    "supportedAlgorithms": ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "AES128", "AES256", "HMAC-SHA256", "HMAC-SHA512"],
    "securityLevel": "strongbox",
    "maxKeys": 256,
    "currentKeys": 12,
    "biometricAvailable": true,
    "attestationSupported": true,
    "ecdhSupported": true
  }
}
```

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| -32700 | Parse Error | Invalid JSON |
| -32600 | Invalid Request | Invalid JSON-RPC structure |
| -32601 | Method Not Found | Unknown method |
| -32602 | Invalid Params | Missing or invalid parameters |
| -32603 | Internal Error | Server-side error |
| -32000 | Key Not Found | Requested key doesn't exist |
| -32001 | User Cancelled | User cancelled biometric prompt |
| -32002 | Biometric Failed | Biometric authentication failed |
| -32003 | Key Exists | Key with that ID already exists |
| -32004 | Unsupported Algorithm | Algorithm not supported |
| -32005 | Invalid Credential ID | Invalid or empty credential ID |
| -32006 | Storage Full | No more keys can be stored |
| -32007 | Operation Timeout | Operation exceeded deadline |
| -32008 | Attestation Failed | Attestation generation failed |
| -32009 | Policy Violation | Operation denied by security policy |

## See Also

- [Phone Backend Architecture](architecture.md)
- [Attestation](attestation.md)
- [Full Protocol Specification](../../../xkey/docs/phone/protocol.md)
