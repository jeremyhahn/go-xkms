# Bidirectional JSON-RPC 2.0 Protocol

> **Status: REFERENCE** · Last verified: 2026-10-13
> Wire background for the xkey phone link; superseded by [phone/architecture.md](architecture.md) and [phone-hsm/api.md](../phone-hsm/api.md). Where they disagree, the feature folders win. Types are in `pkg/pairingproto/protocol*.go`; phone-side (Android app) behaviour is unverified here.

## Overview

The xkey-phone protocol uses JSON-RPC 2.0 over Noise XX encrypted channels. Methods are namespaced by direction:

- `local.*` -- Laptop requests operations on the phone's Android Keystore
- `remote.*` -- Phone requests operations on the laptop's xkmsd backends
- (no prefix) -- The base FIDO2 and pairing methods

Both directions share the same encrypted Noise channel.

## Protocol Basics

| Property | Value |
|----------|-------|
| Version | JSON-RPC 2.0 |
| Encoding | JSON; `[]byte` fields are base64 strings |
| Encryption | `Noise_XX_25519_ChaChaPoly_SHA256` (`pkg/trust/bootstrap/noise_session.go:29`) |
| Transport | BLE GATT, USB (AOA) or TCP; see [transport.md](transport.md) |
| Fragmentation | BLE only, for messages larger than the MTU |
| Request IDs | One process-wide `atomic.Uint64` counter (`requestIDCounter`, `protocol.go:143`) |
| Max message size | `NoiseMaxMessageSize` plaintext (`pkg/trust/bootstrap/noise_session.go:35`) |

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
    "signature": "base64-encoded-signature",
    "algorithm": "ES256"
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
    "message": "key not found"
  }
}
```

---

## `local.*` Methods (Laptop to Phone)

These methods are sent by the laptop and executed on the phone's Android Keystore (TEE/StrongBox). The core set is `pkg/pairingproto/protocol_local.go:28-47`:

| Method | Description |
|--------|-------------|
| `local.generateKey` | Generate a key in Android Keystore |
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
| `local.setKeyPolicy` | Update sharing and authentication policy for a key |
| `local.attestKey` | Get Android Key Attestation for a key |
| `local.attestDevice` | Device-level attestation (see [attestation.md](attestation.md)) |
| `local.verifyUser` | Fresh user-authentication proof (biometric or device credential), for a named RP, by the user-verification key (see [phone-hsm/engineering.md](../phone-hsm/engineering.md#on-demand-user-verification-ruling-167)) |
| `local.getCapabilities` | Query phone capabilities and algorithms |
| `local.listFido2Credentials` | Discover FIDO2 credentials on the phone |
| `local.signFido2Assertion` | Sign a FIDO2 assertion with a phone credential |
| `local.biometricPending` | Notification that the phone is waiting on a biometric prompt |

Parameters and results for each method, with source lines, are in
[android/hsm-protocol.md](android/hsm-protocol.md) and the summary in
[backend/api.md](backend/api.md).

Further `local.*` families live in their own files:

| Family | Methods | Source |
|--------|---------|--------|
| TPM enrollment | `local.getTCGCSRIDevID`, `local.activateCredential`, `local.getAttestationQuote`, `local.getIAKPublicKey`, `local.storeEnrollmentCerts` | `protocol_attestation.go:58-77` |
| IDevID | `local.getCABundle`, `local.getIDevIDCertificate`, `local.requestIDevIDIssuance`, `local.generateIDevIDCSR`, `local.storeIDevIDCertificate` | `protocol_idevid.go:29-45` |
| Device enrollment | `local.getDeviceEnrollmentRequest`, `local.storeDeviceCredential` | `protocol_device_enrollment.go:53-57` |
| Key sharing | `local.sharePublicKey`, `local.shareSymmetric`, `local.importSharedKey` | `protocol_sharing.go:26-34` |
| OATH | `local.oathAdd`, `local.oathList`, `local.oathGenerate`, `local.oathRemove` | `protocol_oath.go:27-37` |
| PIV | `local.pivGenerateKey`, `local.pivImportCert`, `local.pivListSlots`, `local.pivSign`, `local.pivGetCert` | `protocol_piv.go:41-53` |
| Sync | `local.syncTrustStore`, `local.syncOATH`, `local.syncPasswords`, `local.syncStatus` | `protocol_sync.go:28-39` |
| Backup | `local.createBackup`, `local.restoreBackup` | `protocol_backup.go:26-30` |

---

## `remote.*` Methods (Phone to Laptop)

These methods are sent by the phone and served on the laptop by the xkey
bridge, which forwards them to xkmsd (see [bidirectional.md](bidirectional.md)).
The core set is `pkg/pairingproto/protocol_remote.go:20-32`, plus the TPM
enrollment methods at `:60-67`.

| Method | Description |
|--------|-------------|
| `remote.listBackends` | List the xkmsd backends the phone may use |
| `remote.listKeys` | List keys in a backend |
| `remote.getPublicKey` | Get a public key |
| `remote.sign` | Sign data |
| `remote.verify` | Verify a signature |
| `remote.encrypt` | Encrypt data |
| `remote.decrypt` | Decrypt data |
| `remote.deriveKey` | ECDH key agreement |
| `remote.generateKey` | Generate a key on a backend |
| `remote.getKeyInfo` | Get key metadata |
| `remote.deleteKey` | Delete a key |
| `remote.attestKey` | Get key attestation from a backend |
| `remote.attestDevice` | Laptop platform attestation |
| `remote.getTCGCSRIDevID` | Laptop TCG-CSR-IDEVID |
| `remote.activateCredential` | TPM2 credential activation |
| `remote.getAttestationQuote` | TPM2 PCR quote |
| `remote.storeEnrollmentCerts` | Store issued enrollment certificates |

Every key operation names its `backend`; the bridge refuses a backend outside
the sharing policy with `-32008` `ErrorCodeBackendDenied`.

Other `remote.*` families: key sharing (`remote.sharePublicKey`,
`remote.shareSymmetric`, `remote.importSharedKey`, `protocol_sharing.go:38-46`),
OATH (`remote.oathAdd`, `remote.oathGenerate`, `protocol_oath.go:41-45`), PIV
(`remote.pivListSlots`, `remote.pivSign`, `remote.pivGetCert`,
`protocol_piv.go:57-65`), sync (`remote.syncTrustStore`, `remote.syncOATH`,
`remote.syncPasswords`, `remote.syncAll`, `remote.syncStatus`,
`protocol_sync.go:43-59`) and backup (`remote.createBackup`,
`remote.restoreBackup`, `remote.listBackups`, `protocol_backup.go:34-42`).
`remote.createBackup` and `remote.restoreBackup` require a `password`. The
laptop derives the backup key from it exactly as `xkey backup` does, and an
empty one is refused with `-32602`. See
[`../phone-hsm/engineering.md`](../phone-hsm/engineering.md).

### remote.listBackends

No params. Result: `backends`, an array of `BackendInfo`
(`protocol_remote.go:70-79`):

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Backend name |
| `type` | string | Backend type, e.g. `tpm2`, `pkcs11`, `software`, `awskms` |
| `hardwareBacked` | bool | Whether the backend uses hardware |
| `signing` | bool | Supports signing |
| `decryption` | bool | Supports decryption |
| `symmetricCrypto` | bool | Supports symmetric encryption |
| `keyAgreement` | bool | Supports key agreement |
| `attestation` | bool | Supports attestation |

### remote.listKeys

Params: `backend`, optional `algorithm` filter (`protocol_remote.go:88-90`).
Result: `keys`, an array of `RemoteKeyInfo` (`:94-100`):

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | Key identifier |
| `backend` | string | Backend that stores the key |
| `algorithm` | string | Key algorithm |
| `keySizeBits` | int | Key size |
| `label` | string | Key label |
| `createdAt` | int | Creation time (Unix seconds) |

### Key operations

| Method | Params | Result | Source |
|--------|--------|--------|--------|
| `remote.getPublicKey` | `backend`, `keyId`, `format` (`der`, `pem`) | `publicKey`, `format`, `algorithm` | `protocol_remote.go:109-119` |
| `remote.sign` | `backend`, `keyId`, `data`, optional `algorithm` | `signature`, `algorithm` | `:123-133` |
| `remote.verify` | `backend`, `keyId`, `data`, `signature`, optional `algorithm` | `valid` | `:137-147` |
| `remote.encrypt` | `backend`, `keyId`, `plaintext`, optional `algorithm`, `aad` | `ciphertext` | `:151-161` |
| `remote.decrypt` | `backend`, `keyId`, `ciphertext`, optional `algorithm`, `aad` | `plaintext` | `:165-175` |
| `remote.deriveKey` | `backend`, `keyId`, `peerPublicKey` (DER) | `sharedSecret` | `:179-187` |
| `remote.generateKey` | `backend`, `keyId`, `algorithm`, optional `keySizeBits`, `label` | `keyId`, `publicKey` (DER), `algorithm`, `keySizeBits`, `backend` | `:191-205` |
| `remote.getKeyInfo` | `backend`, `keyId` | `RemoteKeyInfo` fields plus `hardwareBacked`, `exportable` | `:209-219` |
| `remote.deleteKey` | `backend`, `keyId` | `deleted` | `:222-229` |

`remote.deriveKey` returns the raw shared secret; there is no KDF parameter.

### remote.attestKey

Params: `backend`, `keyId`, `nonce` (`protocol_remote.go:233-236`). Result
(`:240-244`):

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Attestation format, e.g. `tpm2`, `pkcs11` |
| `certificateChain` | []string | Attestation certificate chain |
| `attestationData` | string | Backend-specific attestation data |
| `nonce` | string | Echoed challenge |

### remote.attestDevice

Params: `nonce`, a 32-byte challenge (`protocol_remote.go:249`). The result
(`:255-267`) carries `format`, `certificateChain`, `securityLevel` and `nonce`,
plus optional `platformPcrs`, `quoteData`, `quoteSignature`,
`firmwareVersion`, `bootHashHex` and `bootStateVerified`. See
[attestation.md](attestation.md).

---

## Base Methods (No Namespace Prefix)

`pkg/pairingproto/protocol.go:35-41`:

| Method | Description |
|--------|-------------|
| `ping` | Health check / keepalive |
| `generateKey` | Generate FIDO2 credential key pair |
| `sign` | Sign data with FIDO2 credential |
| `deleteKey` | Delete FIDO2 credential |
| `loadKey` | Load/verify FIDO2 credential exists |
| `getInfo` | Device information and capabilities |
| `pairing.confirm` | Pairing confirmation |

The FIDO2 methods are documented in the [BLE Protocol Specification](../ble/protocol.md).

---

## Error Code Registry

`pkg/pairingproto/protocol.go:47-139`.

### Standard JSON-RPC Errors

| Code | Constant |
|------|----------|
| -32700 | `ErrorCodeParseError` |
| -32600 | `ErrorCodeInvalidRequest` |
| -32601 | `ErrorCodeMethodNotFound` |
| -32602 | `ErrorCodeInvalidParams` |
| -32603 | `ErrorCodeInternalError` |

### Key and Policy Errors

| Code | Constant |
|------|----------|
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

### Feature Errors

| Code | Constant |
|------|----------|
| -32020 | `ErrorCodeBackupFailed` |
| -32021 | `ErrorCodeBackupRestore` |
| -32022 | `ErrorCodeBackupNotFound` |
| -32023 | `ErrorCodeOATHNotFound` |
| -32024 | `ErrorCodeOATHGenerate` |
| -32025 | `ErrorCodeOATHStore` |
| -32026 | `ErrorCodePIVSlotNotFound` |
| -32027 | `ErrorCodePIVSlotOccupied` |
| -32028 | `ErrorCodePIVSignFailed` |
| -32029 | `ErrorCodePIVInvalidSlot` |
| -32030 | `ErrorCodeSyncFailed` |
| -32031 | `ErrorCodeSyncConflict` |
| -32032 | `ErrorCodeSyncRemoteUnavail` |
| -32033 | `ErrorCodeSyncNoData` |
| -32034 | `ErrorCodeSyncVersionMismatch` |
| -32035 | `ErrorCodeFeatureUnavailable` |
| -32036 | `ErrorCodeNotApplicable` |
| -32037 | `ErrorCodeAttestProtocolDowngrade` |
| -32038 | `ErrorCodeSyncApprovalRequired` |
| -32039 | `ErrorCodeSyncNotApproved` |
| -32040 | `ErrorCodeMessageTooLarge` |

### `local.verifyUser` Refusals

`pkg/pairingproto/verify_user.go:202-210`; a user who cancels the prompt is
`-32001` `ErrorCodeUserCancelled`.

| Code | Constant |
|------|----------|
| -32041 | `ErrorCodeVerifyUserNotEnrolled` |
| -32042 | `ErrorCodeVerifyUserLockout` |
| -32043 | `ErrorCodeNotPaired` |

---

## Message Flow Examples

### Example 1: Generate Key on Phone and Sign Data

```
Laptop                                    Phone
  |                                         |
  |-- local.generateKey ------------------>|
  |   {keyId:"sig-key", algorithm:"ES256", |
  |    strongBoxBacked:true}               |
  |                                         | Generate key in StrongBox
  |<-- result: {publicKeyDer:"...", -------|
  |     securityLevel:"strongbox"}         |
  |                                         |
  |-- local.sign ------------------------->|
  |   {keyId:"sig-key",                    |
  |    algorithm:"ES256",                  |
  |    data:"base64-hash"}                 |
  |                                         | Biometric prompt, if required
  |<-- result: {signature:"..."} ----------|
  |                                         |
```

### Example 2: Phone Signs with Laptop's TPM2 Backend

```
Laptop                                    Phone
  |                                         |
  |<-- remote.listBackends ----------------|
  |                                         |
  |-- result: {backends:[{name:"tpm2", -->|
  |     type:"tpm2", ...}]}                |
  |                                         |
  |<-- remote.sign ------------------------|
  |   {backend:"tpm2",                     |
  |    keyId:"tpm-sign-key",               |
  |    data:"base64-hash"}                 |
  |                                         |
  |   [bridge checks sharing policy,       |
  |    forwards to xkmsd]                  |
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
  |    nonce:"base64-nonce"}               |
  |                                         | Android Key Attestation
  |<-- result: {format:"android-keystore",-|
  |     certificateChain:[...],            |
  |     securityLevel:"strongbox"}         |
  |                                         |
  |<-- remote.attestKey -------------------|
  |   {backend:"tpm2", keyId:"tpm-key",    |
  |    nonce:"base64-nonce"}               |
  |                                         |
  |-- result: {format:"tpm2",  ---------->|
  |     attestationData:"...",             |
  |     certificateChain:[...]}            |
  |                                         |
```

---

## See Also

- [BLE Protocol Specification](../ble/protocol.md) - FIDO2 base protocol details
- [Attestation](attestation.md) - Detailed attestation flows
- [Bidirectional Key Sharing](bidirectional.md) - Sharing design and policies
- [Transport](transport.md) - BLE, USB and TCP transport details
