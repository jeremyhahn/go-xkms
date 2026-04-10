# Remote Key Access (remote.* Client)

## Overview

The Android app can use keys stored on the laptop's xkmsd backends by sending `remote.*` JSON-RPC requests over the same Noise-encrypted channel. The Go binary on the laptop acts as a bridge, forwarding requests to xkmsd via the Go SDK. This allows the phone to sign, encrypt, and decrypt using TPM2, PKCS#11, or any other xkmsd backend without the key material leaving the laptop.

## RemoteKeyClient

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

All methods are suspend functions that send a JSON-RPC request over the Noise channel and await the response. Timeouts are enforced by the underlying `ProtocolHandler`.

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
Noise Encrypted Channel (BLE GATT / TCP)
    |
    v
Go Binary (xkey)
    |
    v
XkmsdBridge
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

### remote.listBackends

List available xkmsd backends.

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
      {"name": "tpm2", "type": "tpm2", "keyCount": 5},
      {"name": "software", "type": "software", "keyCount": 12}
    ]
  }
}
```

### remote.listKeys

List keys in a specific backend.

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
        "keyId": "ssh-ed25519-main",
        "algorithm": "Ed25519",
        "keyType": "ssh",
        "label": "Main SSH Key",
        "createdAt": 1706140800
      }
    ]
  }
}
```

### remote.sign

Sign data with a key on the laptop.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "remote.sign",
  "params": {
    "backend": "tpm2",
    "keyId": "ssh-ed25519-main",
    "data": "base64-encoded-data",
    "algorithm": "Ed25519"
  }
}
```

### remote.getPublicKey

Get public key from a laptop backend key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "remote.getPublicKey",
  "params": {
    "backend": "tpm2",
    "keyId": "ssh-ed25519-main",
    "format": "ssh"
  }
}
```

**Format values:** `der`, `pem`, `ssh`

### remote.encrypt / remote.decrypt

Encrypt or decrypt data with a laptop backend key.

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

Get attestation for a laptop key (TPM2 Certify or PKCS#11 attestation).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "remote.attestKey",
  "params": {
    "backend": "tpm2",
    "keyId": "ssh-ed25519-main",
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
    "attestationType": "tpm2",
    "certifyInfo": "base64-encoded-tpms-attest",
    "signature": "base64-encoded-signature",
    "certificateChain": ["base64-cert-ak", "base64-cert-ek"]
  }
}
```

## Remote Key References in Room

Keys with `source = "xkmsd"` are stored in the `keys` table as references. They contain metadata but no private key material.

| Field | Content |
|-------|---------|
| `keyId` | Key identifier from xkmsd |
| `algorithm` | Algorithm from xkmsd |
| `publicKeyDer` | Cached locally for verification and display |
| `source` | `"xkmsd"` |
| `key_type` | Matches xkmsd key type |
| `label` | Backend name + key label |

Operations on these keys are proxied through `RemoteKeyClient`, not the local Android Keystore. The `KeystoreManager` is never invoked for xkmsd-sourced keys.

## Key Management UI Integration

The Key Management screen shows both local and remote keys.

| Key Source | Icon | Operations Available |
|------------|------|---------------------|
| Local (Android Keystore) | Hardware chip icon | Sign, encrypt, decrypt, delete, export public key |
| Remote (xkmsd) | Laptop icon | Sign, encrypt, decrypt (proxied), view info |

**Key list display:**
- Keys are grouped by source (Local / Remote)
- Each key shows: label, algorithm, key type, last used time
- Tapping a remote key shows the backend name, key details, and cached public key
- Pull-to-refresh syncs remote key list via `remote.listBackends` and `remote.listKeys`

## Sharing Policy

The phone respects the laptop's sharing policy configured in `~/.config/xkey/config.yaml`:

```yaml
phone:
  xkmsd:
    sharing:
      policy: "shared"              # "private" or "shared"
      allowed_backends: ["tpm2", "software"]
      denied_backends: ["vault"]
```

| Policy | Behavior |
|--------|----------|
| `private` | Phone sees no remote keys. `remote.listBackends` returns empty. |
| `shared` | Phone sees backends in `allowed_backends`. Denied backends are filtered out. |

The Go binary enforces the policy before forwarding requests. If the phone requests an operation on a denied backend, it receives a `-32001` error (access denied).

## Use Cases

### SSH Signing with Laptop TPM2 Key

The phone's terminal app needs to authenticate an SSH session using the laptop's TPM2-backed SSH key.

```
Phone terminal app -> RemoteKeyClient.sign("tpm2", "ssh-main", challenge, "Ed25519")
    -> Noise channel -> Go binary -> xkmsd -> TPM2 -> signature
    -> Phone terminal app verifies and completes SSH handshake
```

### Encryption with Laptop PKCS#11 Key

The phone encrypts sensitive data using the laptop's PKCS#11-backed RSA encryption key.

```
Phone app -> RemoteKeyClient.encrypt("pkcs11", "rsa-enc", plaintext)
    -> Noise channel -> Go binary -> xkmsd -> PKCS#11 HSM -> ciphertext
    -> Phone app stores encrypted data
```

### Unified Key Inventory

The phone lists all available keys across both local and remote stores.

```kotlin
// Local keys from Room
val localKeys = keyDao.getByType("signing")

// Remote keys from xkmsd
val backends = remoteKeyClient.listBackends()
val remoteKeys = backends.flatMap { backend ->
    remoteKeyClient.listKeys(backend.name)
}

// Combined view
val allKeys = localKeys.map { it.toKeyInfo() } + remoteKeys.map { it.toKeyInfo() }
```

## Error Handling

Remote key errors map to JSON-RPC error codes.

| Scenario | JSON-RPC Code | Message |
|----------|---------------|---------|
| Backend not found | -32000 | Backend does not exist |
| Access denied (policy) | -32001 | Backend access denied by sharing policy |
| Key not found | -32000 | Key not found in backend |
| Laptop disconnected | -32005 | Connection lost during operation |
| xkmsd unavailable | -32603 | xkmsd service not reachable |
