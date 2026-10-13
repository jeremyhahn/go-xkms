# Phone Backend API Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> `local.*` wire summary for the phone backend; superseded by [phone-hsm/api.md](../../phone-hsm/api.md). Where they disagree, the feature folder wins. Types are in `xkey/pkg/pairing/protocol_local.go`; byte fields are base64 on the wire.

## Overview

The phone backend uses JSON-RPC 2.0 over Noise XX encrypted channels. Methods in the `local.*` namespace are sent from the laptop to the phone, requesting operations on the phone's Android Keystore. The per-method reference with field lists is [android/hsm-protocol.md](../android/hsm-protocol.md).

## Method Summary

| Method | Description | Result fields |
|--------|-------------|---------------|
| `local.generateKey` | Generate key with specified algorithm | `keyId`, `publicKeyDer`/`publicKeyCose`, `algorithm`, `keySizeBits`, `securityLevel` |
| `local.sign` | Sign data with key | `signature`, `algorithm` |
| `local.decrypt` | RSA decryption | `plaintext` |
| `local.symmetricEncrypt` | AES-GCM encryption | `ciphertext` (IV + data + tag) |
| `local.symmetricDecrypt` | AES-GCM decryption | `plaintext` |
| `local.hmac` | HMAC computation | `mac` |
| `local.ecdh` | ECDH key agreement | `sharedSecret` |
| `local.getPublicKey` | Export public key | `publicKey`, `format`, `algorithm` |
| `local.listKeys` | List keys, optional `keyType`/`algorithm` filters | `keys` |
| `local.getKeyInfo` | Detailed key metadata | key info object |
| `local.deleteKey` | Delete key from phone | `deleted` |
| `local.setKeyPolicy` | Update sharing/auth policy | `updated` |
| `local.attestKey` | Android Key Attestation | `format`, `certificateChain`, `securityLevel`, `nonce` |
| `local.getCapabilities` | Phone capabilities | see below |
| `ping` | Connection health check | — |
| `getInfo` | Device information | — |

`ping` and `getInfo` are the base methods in `xkey/pkg/pairing/protocol.go`.

## Key Generation

### `local.generateKey`

`LocalGenerateKeyParams` (`protocol_local.go:53`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "local.generateKey",
  "params": {
    "keyId": "my-signing-key",
    "algorithm": "ES256",
    "strongBoxBacked": true,
    "biometricRequired": true,
    "authDurationSeconds": 5
  }
}
```

Other params: `keySizeBits` (RSA: 2048, 3072, 4096), `userVerificationRequired`, `exportable` (symmetric only).

**Supported algorithms:** `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`, `AES128`, `AES256`, `HMAC-SHA256`, `HMAC-SHA512`

**Response** (`LocalGenerateKeyResult`, `protocol_local.go:69`):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "keyId": "my-signing-key",
    "publicKeyDer": "<base64>",
    "algorithm": "ES256",
    "keySizeBits": 256,
    "securityLevel": "strongbox"
  }
}
```

## Signing

### `local.sign`

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "local.sign",
  "params": {
    "keyId": "my-signing-key",
    "data": "<base64 data>",
    "algorithm": "ES256"
  }
}
```

**Response:** `{"signature": "<base64 DER-encoded signature>", "algorithm": "ES256"}`

## Decryption

### `local.decrypt`

RSA decryption; the optional `algorithm` names the scheme, e.g.
`RSA-OAEP-SHA256` (`LocalDecryptParams`, `protocol_local.go:93`).

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "local.decrypt",
  "params": {
    "keyId": "my-rsa-key",
    "ciphertext": "<base64>",
    "algorithm": "RSA-OAEP-SHA256"
  }
}
```

**Response:** `{"plaintext": "<base64>"}`

## Symmetric Encryption

### `local.symmetricEncrypt` / `local.symmetricDecrypt`

AES-GCM. The ciphertext carries the IV and tag: IV + encrypted data + tag
(`protocol_local.go:105-120`); there is no separate `nonce` field.

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

**Encrypt response:** `{"ciphertext": "<base64 IV + data + tag>"}`

Decrypt takes `keyId`, `ciphertext` and optional `aad`, and returns `plaintext`.

## HMAC

### `local.hmac`

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

**Response:** `{"mac": "<base64>"}`

## ECDH Key Agreement

### `local.ecdh`

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

**Response:** `{"sharedSecret": "<base64>"}`

## Public Key Export

### `local.getPublicKey`

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

**Response:** `{"publicKey": "<base64>", "format": "der", "algorithm": "ES256"}`

## Key Management

### `local.listKeys`

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

### `local.getKeyInfo` / `local.deleteKey`

Both take `{"keyId": "my-signing-key"}`.

### `local.setKeyPolicy`

Absent fields are left unchanged (`LocalSetKeyPolicyParams`, `protocol_local.go:223`):

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

See [attestation.md](attestation.md).

### `local.getCapabilities`

Takes no parameters. **Response** (`LocalGetCapabilitiesResult`, `protocol_local.go:334`):

```json
{
  "jsonrpc": "2.0",
  "id": 14,
  "result": {
    "version": "1.0",
    "deviceName": "Pixel-8",
    "supportedAlgorithms": ["ES256", "ES384", "ES512", "RS256", "AES256", "HMAC-SHA256"],
    "strongBoxAvailable": true,
    "maxKeys": 256,
    "currentKeyCount": 12,
    "supportedFormats": ["der", "pem", "ssh", "cose"],
    "attestationSupport": true
  }
}
```

## Error Codes

From `xkey/pkg/pairing/protocol.go:47`; the full list continues past `-32019`
with backup, OATH, PIV and sync codes.

| Code | Constant |
|------|----------|
| -32700 | `ErrorCodeParseError` (standard) |
| -32600 | invalid request (standard) |
| -32601 | method not found (standard) |
| -32602 | invalid params (standard) |
| -32603 | internal error (standard) |
| -32000 | `ErrorCodeKeyNotFound` |
| -32001 | `ErrorCodeUserCancelled` |
| -32002 | `ErrorCodeBiometricFailed` |
| -32003 | `ErrorCodeKeyExists` |
| -32004 | `ErrorCodeUnsupportedAlg` |
| -32005 | `ErrorCodeInvalidCredID` |
| -32006 | `ErrorCodeStorageFull` |
| -32007 | `ErrorCodeOperationTimeout` |
| -32008 | `ErrorCodeBackendDenied` |
| -32009 | `ErrorCodeAttestFailed` |
| -32010 | `ErrorCodeAttestUnsupported` |
| -32011 | `ErrorCodeOperationDenied` |
| -32012 | `ErrorCodeInvalidPublicKey` |
| -32013 | `ErrorCodeDecryptFailed` |
| -32014 | `ErrorCodeHMACFailed` |
| -32015 | `ErrorCodeECDHFailed` |
| -32016 | `ErrorCodeInvalidFormat` |
| -32017 | `ErrorCodePairingRejected` |
| -32018 | `ErrorCodeShareDenied` |
| -32019 | `ErrorCodeShareNotExportable` |

## See Also

- [Phone Backend Architecture](architecture.md)
- [Attestation](attestation.md)
- [Full Protocol Specification](../protocol.md)
