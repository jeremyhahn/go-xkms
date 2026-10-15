# Remote Key Access (remote.* Client)

> **Status: REFERENCE** · Last verified: 2026-10-13
> Wire reference for the `remote.*` methods; superseded by [phone-hsm/api.md](../../phone-hsm/api.md). The phone-side `RemoteKeyClient`, Room references and UI belong to xkey-android, a separate Kotlin repository, and are not verifiable here; the Go wire types (`pkg/pairingproto/protocol_remote.go`) and the bridge are.

## Overview

The Android app can use keys stored on the laptop's xkmsd backends by sending `remote.*` JSON-RPC requests over the same Noise-encrypted channel. The Go binary on the laptop acts as a bridge, forwarding requests to xkmsd via the Go SDK. This allows the phone to sign, encrypt, and decrypt using TPM2, PKCS#11, or any other xkmsd backend without the key material leaving the laptop.

## RemoteKeyClient

Phone-side sketch (xkey-android, unverified here):

```kotlin
class RemoteKeyClient(
    private val protocolHandler: ProtocolHandler
) {
    suspend fun listBackends(): List<BackendInfo>
    suspend fun listKeys(backend: String): List<RemoteKeyInfo>
    suspend fun sign(backend: String, keyId: String, data: ByteArray, algorithm: String): ByteArray
    suspend fun getPublicKey(backend: String, keyId: String, format: String): ByteArray
    suspend fun encrypt(backend: String, keyId: String, plaintext: ByteArray): ByteArray
    suspend fun decrypt(backend: String, keyId: String, ciphertext: ByteArray): ByteArray
    suspend fun attestKey(backend: String, keyId: String, nonce: ByteArray): AttestationResult
}
```

## Data Flow

```
Phone App
    |
    v
RemoteKeyClient
    |
    v
JSON-RPC "remote.*" request
    |
    v
Noise Encrypted Channel (BLE GATT / USB / TCP)
    |
    v
Go Binary (xkey)
    |
    v
Bridge (xkey/pkg/pairing/bridge.go)
    |
    v
Go SDK (go-xkms SDK)
    |
    v
xkmsd service
    |
    v
Backend (TPM2 / PKCS#11 / Software / Cloud KMS)
    |
    v
Response back through the same path
```

## Method Reference

Method names are the constants in `pkg/pairingproto/protocol_remote.go:20`:
`listBackends`, `listKeys`, `getPublicKey`, `sign`, `verify`, `encrypt`,
`decrypt`, `deriveKey`, `generateKey`, `getKeyInfo`, `deleteKey`, `attestKey`,
`attestDevice`, `getTCGCSRIDevID`, `activateCredential`,
`getAttestationQuote` and `storeEnrollmentCerts`, each prefixed `remote.`.
Byte fields are base64 strings on the wire.

### remote.listBackends

List available xkmsd backends. Each entry is a `BackendInfo`
(`protocol_remote.go:71`): `name`, `type`, `hardwareBacked` and the capability
flags `signing`, `decryption`, `symmetricCrypto`, `keyAgreement`,
`attestation`.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "remote.listBackends"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "backends": [
      {"name": "tpm2", "type": "tpm2", "hardwareBacked": true, "signing": true, "decryption": true, "symmetricCrypto": false, "keyAgreement": false, "attestation": true}
    ]
  }
}
```

### remote.listKeys

List keys in a specific backend, optionally filtered by `algorithm`
(`RemoteListKeysParams`, `protocol_remote.go:88`). Each key is a
`RemoteKeyInfo` (`protocol_remote.go:94`).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "remote.listKeys",
  "params": {
    "backend": "tpm2"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "keys": [
      {
        "keyId": "signing-main",
        "backend": "tpm2",
        "algorithm": "ES256",
        "keySizeBits": 256,
        "label": "Main Signing Key",
        "createdAt": 1706140800
      }
    ]
  }
}
```

### remote.sign

Sign data with a key on the laptop (`RemoteSignParams`,
`protocol_remote.go:123`).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "remote.sign",
  "params": {
    "backend": "tpm2",
    "keyId": "signing-main",
    "data": "base64-encoded-data",
    "algorithm": "ES256"
  }
}
```

### remote.getPublicKey

Get the public key of a laptop backend key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "remote.getPublicKey",
  "params": {
    "backend": "tpm2",
    "keyId": "signing-main",
    "format": "pem"
  }
}
```

**Format values:** `der`, `pem` (`RemoteGetPublicKeyParams`, `protocol_remote.go:109`)

### remote.encrypt / remote.decrypt

Encrypt or decrypt data with a laptop backend key. Encrypt also accepts
optional `algorithm` and `aad` (`RemoteEncryptParams`,
`protocol_remote.go:151`).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "remote.encrypt",
  "params": {
    "backend": "pkcs11",
    "keyId": "rsa-encryption-key",
    "plaintext": "base64-encoded-plaintext"
  }
}
```

### remote.attestKey

Get attestation for a laptop key (`RemoteAttestKeyParams`,
`protocol_remote.go:233`). The result (`RemoteAttestKeyResult`,
`protocol_remote.go:240`) carries `format`, `certificateChain`,
`attestationData` and the echoed `nonce`.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "remote.attestKey",
  "params": {
    "backend": "tpm2",
    "keyId": "signing-main",
    "nonce": "base64-encoded-nonce"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "format": "tpm2",
    "certificateChain": ["base64-cert-ak", "base64-cert-ek"],
    "attestationData": "base64-encoded-attestation",
    "nonce": "base64-encoded-nonce"
  }
}
```

## Remote Key References in Room

Phone-side behaviour of xkey-android, unverified here. Keys with `source = "xkmsd"` are stored in the phone's `keys` table as references: metadata and a cached public key, no private key material. Operations on them are proxied through `RemoteKeyClient`, never the local Android Keystore.

## Key Management UI Integration

Phone-side behaviour of xkey-android, unverified here. The Key Management screen groups keys by source (Local / Remote) and refreshes the remote list with `remote.listBackends` and `remote.listKeys`.

## Sharing Policy

The laptop decides which backends the phone may reach. `xkey` reads the
backend lists from the `xkmsd.sharing` section of its config
(`xkey/cmd/xkey/cmd/dial_xkmsd.go:95-96`):

```yaml
xkmsd:
  sharing:
    allowed_backends: ["tpm2", "software"]   # empty = all backends
    denied_backends: ["vault"]
```

These populate `BridgeConfig.AllowedBackends` and `DeniedBackends`
(`xkey/pkg/pairing/bridge.go:39`). The bridge enforces them before forwarding a
request; an operation on a backend that is not allowed fails with `-32008`
`ErrorCodeBackendDenied`, "backend access denied" (`bridge.go:1017`). Per-key
sharing is a separate policy (`xkey/pkg/pairing/sharing_policy.go`).

## Use Cases

### Signing with a Laptop TPM2 Key

```
Phone app -> remote.sign("tpm2", "signing-main", data, "ES256")
    -> Noise channel -> Go binary -> xkmsd -> TPM2 -> signature
```

### Encryption with a Laptop PKCS#11 Key

```
Phone app -> remote.encrypt("pkcs11", "rsa-enc", plaintext)
    -> Noise channel -> Go binary -> xkmsd -> PKCS#11 HSM -> ciphertext
```

## Error Handling

Remote key errors use the JSON-RPC codes in `pkg/pairingproto/protocol.go:47`,
including:

| Code | Constant |
|------|----------|
| -32000 | `ErrorCodeKeyNotFound` |
| -32004 | `ErrorCodeUnsupportedAlg` |
| -32007 | `ErrorCodeOperationTimeout` |
| -32008 | `ErrorCodeBackendDenied` |
| -32009 | `ErrorCodeAttestFailed` |
| -32010 | `ErrorCodeAttestUnsupported` |
| -32013 | `ErrorCodeDecryptFailed` |
| -32016 | `ErrorCodeInvalidFormat` |
| -32603 | standard internal error |
