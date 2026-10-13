# Phone Backend Architecture

> **Status: REFERENCE** · Last verified: 2026-10-13
> Architecture background for the xkmsd phone backend (`pkg/backend/phone`); superseded by [phone-hsm/architecture.md](../../phone-hsm/architecture.md). Where they disagree, the feature folder wins. Phone-side (Android) behaviour is unverified here.

## Overview

The phone backend is an xkmsd backend that delegates all cryptographic operations to an Android phone. It implements the `types.KeyProvider` interface family, making the phone a backend alongside TPM2, PKCS#11 and software.

The Android phone's hardware-backed Keystore (TEE/StrongBox) serves as the cryptographic engine, with biometric authentication gating access to key material. The backend itself holds no connection: it sends every request through a `Sender` (`pkg/backend/phone/backend.go:39`) supplied by the embedder that owns the Noise XX session with the phone.

```
+-----------------------------------------------------------------------+
|                        xkmsd Server                                   |
+-----------------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------------+
|                       Phone Backend                                   |
|                   pkg/backend/phone                                   |
+-----------------------------------------------------------------------+
|  KeyProvider | Attestation | Symmetric  | KeyAgreement | ImportExport |
|  (core ops)  | (Android KA)| (AES-GCM)  | (ECDH)       | (pub only)   |
+--------------+-------------+------------+--------------+--------------+
                                |
                                v Sender.SendRequest (JSON-RPC)
+-----------------------------------------------------------------------+
|              Embedder-owned Noise XX session                          |
|              BLE (GATT)  |  TCP (ADB port forward)                    |
+-----------------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------------+
|                       Android Phone                                   |
|  +-----------------------------+  +--------------------------------+  |
|  | Biometric Authentication    |  | Android Keystore               |  |
|  | (Fingerprint / Face)        |  | (TEE / StrongBox)              |  |
|  +-----------------------------+  +--------------------------------+  |
+-----------------------------------------------------------------------+
```

## Package Structure

```
pkg/backend/phone/
+-- backend.go           # Backend, Sender, core key ops, JSON-RPC error mapping
+-- attestation.go       # types.AttestingKeyProvider (Android Key Attestation)
+-- platform.go          # PlatformVerifier registry (RegisterPlatform)
+-- config.go            # Config, AttestationConfig, defaults
+-- errors.go            # Typed errors
+-- signer.go            # crypto.Signer proxy to phone
+-- decrypter.go         # crypto.Decrypter proxy to phone
+-- symmetric.go         # types.SymmetricKeyProvider implementation
+-- key_agreement.go     # types.KeyAgreementProvider (ECDH)
+-- import_export.go     # ImportExportBackend (public key export only)
+-- fido2.go             # FIDO2 credential listing on the phone
+-- doc.go               # Package documentation
+-- android/             # Android Key Attestation verifier
```

## Interfaces Implemented

| Interface | Assertion | Phone methods used |
|-----------|-----------|--------------------|
| `types.KeyProvider` | `backend.go:111` | `local.generateKey`, `local.getKeyInfo`, `local.getPublicKey`, `local.deleteKey`, `local.listKeys` |
| `crypto.Signer` (per key) | `signer.go:34` | `local.sign` — the pre-hashed digest is sent as `data` (`signer.go:57`) |
| `crypto.Decrypter` (per key) | `decrypter.go:76` | `local.decrypt` |
| `types.AttestingKeyProvider` | `attestation.go:25` | `local.attestKey` |
| `types.SymmetricKeyProvider` | `symmetric.go:27` | `local.generateKey`, `local.symmetricEncrypt`, `local.symmetricDecrypt` |
| `types.KeyAgreementProvider` | `key_agreement.go:24` | `local.ecdh` |
| `backend.ImportExportBackend` | `import_export.go:25` | `local.getPublicKey`; import and private export return `ErrImportNotSupported` / `ErrExportNotSupported` |

`RotateKey` returns `ErrRotationNotSupported` (`backend.go:439`). There is no
`local.verify` or `local.encrypt` method; the full `local.*` set is
`localMethodNames` (`xkey/pkg/pairing/protocol_local.go:392`).

## Transport and Noise

The backend validates `transport` (`ble` or `tcp`), `device_address` and both
static keys, but never opens a connection or reads `NoiseStaticKey`
(`pkg/server/backend_phone.go:91`). The embedder that owns the phone link
performs the Noise XX handshake and passes a `Sender` to
`Server.RegisterPhoneBackend` (`pkg/server/backend_phone.go:58`). Nothing in
this repository calls it, so a stock xkmsd never registers the backend.

The transports and their framing are documented in
[../transport.md](../transport.md); the Noise handshake and pairing in
[../protocol.md](../protocol.md) and phone-hsm's
[architecture.md](../../phone-hsm/architecture.md).

### XX Handshake Pattern

```
Initiator (Laptop)                        Responder (Phone)
     |                                         |
     |  e -->                                  |
     |-----------------------------------------|
     |                              <-- e, ee, s, es
     |-----------------------------------------|
     |  s, se -->                              |
     |-----------------------------------------|
     |  [Transport session established]        |
     |  [Both sides authenticated]             |
```

- **Static keys**: generated during `xkey device pair` and stored in `devices.yaml`
- **Ephemeral keys**: fresh per connection, for forward secrecy
- **Session keys**: derived from the handshake; new on every reconnection

## Key Operation Flow

### Sign

```
xkmsd                Phone Backend           Sender (Noise)          Phone
    |                         |                       |                    |
    | Signer(attrs).Sign(dgst)|                       |                    |
    |------------------------>|                       |                    |
    |                         | local.sign            |                    |
    |                         |---------------------->|------------------->|
    |                         |                       |                    | biometric
    |                         |                       |                    | prompt (if key
    |                         |                       |                    | requires it)
    |                         |                       |                    | Keystore signs
    |                         | <-- signature --------|<-------------------|
    | <-- signature           |                       |                    |
```

### Attestation

```
xkmsd                Phone Backend           Phone (Android Keystore)
    |                         |                       |
    | AttestKey(attrs, nonce) |                       |
    |------------------------>|                       |
    |                         | local.attestKey       |
    |                         |---------------------->|
    |                         | <-- X.509 cert chain  |
    |                         |                       |
    |                         | platform verifier,    |
    |                         | only if configured    |
    | <-- AttestationResult   |                       |
```

`Verified` is `false` unless `Config.Attestation` is set; see
[attestation.md](attestation.md).

## Bidirectional Use

`local.*` requests flow from the laptop to the phone through this backend.
`remote.*` requests flow the other way — the phone using laptop keys — and are
served by the xkey bridge (`xkey/pkg/pairing/bridge.go`), not by this package.
The `remote.*` set is in `xkey/pkg/pairing/protocol_remote.go:20-32`; see
[../bidirectional.md](../bidirectional.md).

## Error Handling

All errors are typed in `errors.go`. `mapRPCError` translates JSON-RPC error
codes through `rpcErrorMapping` (`backend.go:90`):

| JSON-RPC code | Go error |
|---------------|----------|
| -32000 `KeyNotFound` | `ErrKeyNotFound` |
| -32001 `UserCancelled` | `ErrUserCancelled` |
| -32002 `BiometricFailed` | `ErrBiometricFailed` |
| -32003 `KeyExists` | `ErrKeyExists` |
| -32004 `UnsupportedAlg` | `ErrUnsupportedAlgorithm` |
| -32007 `OperationTimeout` | `ErrOperationTimeout` |
| -32009 `AttestFailed` | `ErrAttestationFailed` |
| -32012 `InvalidPublicKey` | `ErrInvalidPublicKey` |
| -32603 internal error | `ErrInvalidResponse` |
| -32700, -32600, -32601, -32602, -32008, -32010, -32011, -32013 | `ErrProtocolError` |

Other notable errors: `ErrNotConnected`, `ErrBackendClosed`,
`ErrConnectionLost`, `ErrTransportUnavailable`, `ErrRotationNotSupported`,
`ErrExportNotSupported`, `ErrImportNotSupported`, `ErrChainVerificationFailed`,
`ErrInsufficientSecurityLevel`, `ErrUnsupportedPlatform`.

## Security Model

| Property | Mechanism |
|----------|-----------|
| Confidentiality and integrity | Noise XX transport encryption |
| Mutual authentication | Static key verification during the XX handshake |
| Forward secrecy | Ephemeral keys per connection |
| Key binding | Android Keystore TEE/StrongBox hardware binding |
| User presence | Biometric prompt for keys created with `biometricRequired` |
| Attestation | Android Key Attestation, verified only when a verifier is configured |

See [security.md](security.md) for the threat model.

## Capabilities

`Capabilities()` (`backend.go:191`) — the full literal is in
[README.md](README.md#capabilities): keys, hardware-backed, signing,
decryption, symmetric encryption, key agreement and attestation are `true`;
rotation, sealing, import and export are `false`; security level is
`SecurityLevelHigh`.

### Algorithm Mapping

`algorithmMapping` (`backend.go:71`) maps key attributes to phone algorithm
names:

| Key | Phone algorithm |
|-----|-----------------|
| ECDSA P-256 / P-384 / P-521 | `ES256` / `ES384` / `ES512` |
| RSA SHA-256 (default) / SHA-384 / SHA-512 | `RS256` / `RS384` / `RS512` |
| Ed25519 | `EdDSA` |

Which of these a given phone supports is reported by `local.getCapabilities`.

## See Also

- [Phone overview](../README.md)
- [Configuration](configuration.md)
- [CLI](../../phone-hsm/cli.md)
