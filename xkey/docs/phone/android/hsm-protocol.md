# HSM Protocol Handler (local.* Methods)

> **Status: REFERENCE** · Last verified: 2026-10-13
> Wire reference for the `local.*` methods; superseded by [phone-hsm/api.md](../../phone-hsm/api.md). Phone-side (xkey-android, Kotlin) internals are out of scope: only the Go wire types in `xkey/pkg/pairing` are verified here.

## Overview

The Android app (xkey-android, a separate repository) handles `local.*` JSON-RPC requests from the laptop. These requests arrive over the Noise-encrypted BLE, USB or TCP channel and are served by the Android Keystore. The phone effectively operates as a remote HSM for the laptop.

The desktop side defines every method name and its params/result types in
`xkey/pkg/pairing/protocol_local.go`; `IsLocalMethod` (`protocol_local.go:418`)
validates names against the `localMethodNames` map (`protocol_local.go:392`).
Byte fields (`[]byte` in Go) are base64 strings on the wire (Go's
`encoding/json` default).

## Methods

| Method | Params type | Result type |
|--------|-------------|-------------|
| `local.generateKey` | `LocalGenerateKeyParams` | `LocalGenerateKeyResult` |
| `local.sign` | `LocalSignParams` | `LocalSignResult` |
| `local.decrypt` | `LocalDecryptParams` | `LocalDecryptResult` |
| `local.symmetricEncrypt` | `LocalSymmetricEncryptParams` | `LocalSymmetricEncryptResult` |
| `local.symmetricDecrypt` | `LocalSymmetricDecryptParams` | `LocalSymmetricDecryptResult` |
| `local.hmac` | `LocalHMACParams` | `LocalHMACResult` |
| `local.ecdh` | `LocalECDHParams` | `LocalECDHResult` |
| `local.getPublicKey` | `LocalGetPublicKeyParams` | `LocalGetPublicKeyResult` |
| `local.listKeys` | `LocalListKeysParams` | `LocalListKeysResult` |
| `local.getKeyInfo` | `LocalGetKeyInfoParams` | `LocalGetKeyInfoResult` |
| `local.deleteKey` | `LocalDeleteKeyParams` | `LocalDeleteKeyResult` |
| `local.setKeyPolicy` | `LocalSetKeyPolicyParams` | `LocalSetKeyPolicyResult` |
| `local.attestKey` | `LocalAttestKeyParams` | `LocalAttestKeyResult` |
| `local.attestDevice` | `LocalAttestDeviceParams` | `LocalAttestDeviceResult` |
| `local.getCapabilities` | (none) | `LocalGetCapabilitiesResult` |
| `local.listFido2Credentials` | `LocalListFido2CredentialsParams` | `LocalListFido2CredentialsResult` |
| `local.signFido2Assertion` | `LocalSignFido2AssertionParams` | `LocalSignFido2AssertionResult` |
| `local.biometricPending` | `LocalBiometricPendingParams` (phone → laptop notification) | — |

The OATH, PIV, sharing, sync, backup, IDevID and device-enrollment `local.*`
methods are defined in the sibling `protocol_*.go` files; see
[../protocol.md](../protocol.md).

## Method Reference

### local.generateKey

Generate a new key in Android Keystore (`LocalGenerateKeyParams`,
`protocol_local.go:53`). `algorithm` accepts `ES256`, `ES384`, `ES512`,
`RS256`, `RS384`, `RS512`, `AES128`, `AES256`, `HMAC-SHA256`, `HMAC-SHA512`.
`exportable` requests a software-backed key and is only valid for symmetric
algorithms.

**Request:**
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

Other params: `keySizeBits` (RSA: 2048, 3072, 4096), `userVerificationRequired`, `exportable`.

**Response** (`LocalGenerateKeyResult`, `protocol_local.go:69`):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "keyId": "my-signing-key",
    "publicKeyDer": "base64-encoded-der",
    "algorithm": "ES256",
    "keySizeBits": 256,
    "securityLevel": "strongbox"
  }
}
```

`publicKeyCose` may be returned instead of, or alongside, `publicKeyDer`.
`securityLevel` is `tee` or `strongbox`.

### local.sign

Sign data with a stored key (`LocalSignParams`, `protocol_local.go:79`).
`algorithm` optionally overrides the signing algorithm.

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
    "signature": "base64-encoded-der-signature",
    "algorithm": "ES256"
  }
}
```

### local.decrypt

RSA decryption (`LocalDecryptParams`, `protocol_local.go:93`); optional
`algorithm`, e.g. `RSA-OAEP-SHA256`. Result: `plaintext`.

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

AES encryption and decryption with optional `aad`
(`protocol_local.go:105`, `:117`). The ciphertext is IV + encrypted data + tag.

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

Decrypt takes `keyId`, `ciphertext`, `aad` and returns `plaintext`.

### local.hmac

Compute an HMAC over `data` (`protocol_local.go:129`). Result: `mac`.

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

ECDH key agreement against a DER-encoded peer public key
(`protocol_local.go:140`). Result: `sharedSecret`.

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

Export a public key in the requested format (`protocol_local.go:151`).
Result: `publicKey`, `format`, `algorithm`.

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

List keys, optionally filtered by `keyType` (`fido2`, `ssh`, `tls`, `signing`,
`encryption`, `symmetric`) and `algorithm` (`protocol_local.go:164`). Result:
`keys`, an array of `KeyInfo` (`protocol_local.go:170`).

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

Get metadata for one key. The result embeds `KeyInfo` and, for `fido2` keys,
adds `rpId`, `rpName`, `userId`, `userName`, `userDisplayName`,
`isDiscoverable` and `signCount` (`LocalGetKeyInfoResult`,
`protocol_local.go:198`).

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
    "label": "Code Signing Key",
    "strongBoxBacked": true,
    "biometricRequired": true,
    "exportable": false,
    "shareable": false,
    "source": "local",
    "useCount": 42,
    "createdAt": 1706140800,
    "lastUsedAt": 1706227200
  }
}
```

`source` is one of `local`, `remote_ble`, `remote_usb`, `xkmsd`.

### local.deleteKey

Delete a key (`protocol_local.go:212`). Result: `deleted`.

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

Update the policy fields `shareable`, `biometricRequired` and
`authDurationSeconds`; an absent field is left unchanged
(`LocalSetKeyPolicyParams`, `protocol_local.go:223`). Result: `updated`.

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "local.setKeyPolicy",
  "params": {
    "keyId": "my-signing-key",
    "shareable": true
  }
}
```

### local.attestKey

Get the Android Key Attestation certificate chain for a key
(`protocol_local.go:236`). Result (`LocalAttestKeyResult`,
`protocol_local.go:242`): `format` (`android-keystore`), `certificateChain`
(leaf first), `securityLevel`, and the echoed `nonce`.

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "local.attestKey",
  "params": {
    "keyId": "my-signing-key",
    "nonce": "base64-encoded-nonce"
  }
}
```

### local.getCapabilities

Takes no parameters (`LocalGetCapabilitiesResult`, `protocol_local.go:334`).

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 13,
  "result": {
    "version": "1.0",
    "deviceName": "Pixel-8",
    "supportedAlgorithms": ["ES256", "ES384", "ES512", "RS256"],
    "strongBoxAvailable": true,
    "maxKeys": 100,
    "currentKeyCount": 3,
    "supportedFormats": ["der", "pem", "ssh", "cose"],
    "attestationSupport": true
  }
}
```

## Biometric gating

`biometricRequired` and `authDurationSeconds` are set at generation and can be
changed with `local.setKeyPolicy`. While the phone waits for the user it may
send a `local.biometricPending` notification carrying `operation`, `rpName`
and `timeoutSecs` (`LocalBiometricPendingParams`, `protocol_local.go:385`).

## Error codes

Errors use the JSON-RPC codes in `xkey/pkg/pairing/protocol.go:47`: the
standard `-32700`, `-32600`, `-32601`, `-32602`, `-32603`, and the
application range starting at `-32000`, including:

| Code | Constant |
|------|----------|
| -32000 | `ErrorCodeKeyNotFound` |
| -32001 | `ErrorCodeUserCancelled` |
| -32002 | `ErrorCodeBiometricFailed` |
| -32003 | `ErrorCodeKeyExists` |
| -32004 | `ErrorCodeUnsupportedAlg` |
| -32007 | `ErrorCodeOperationTimeout` |
| -32009 | `ErrorCodeAttestFailed` |
| -32010 | `ErrorCodeAttestUnsupported` |
| -32013 | `ErrorCodeDecryptFailed` |
| -32014 | `ErrorCodeHMACFailed` |
| -32015 | `ErrorCodeECDHFailed` |
| -32016 | `ErrorCodeInvalidFormat` |
