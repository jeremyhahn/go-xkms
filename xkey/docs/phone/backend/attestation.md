# Phone Backend Key Attestation

> **Status: REFERENCE** · Last verified: 2026-10-13
> Attestation background for the xkmsd phone backend; superseded by [phone-hsm/architecture.md](../../phone-hsm/architecture.md) and [phone/attestation.md](../attestation.md). Where they disagree, the feature folders win.

## Overview

The phone backend supports Android Key Attestation, which produces X.509 certificate chains proving that keys are stored in hardware (TEE or StrongBox). The attestation chain roots to Google's hardware attestation root CA, providing a trusted third-party guarantee of hardware backing.

## Attestation Levels

| Level | What's Proven | Mechanism |
|-------|--------------|-----------|
| Transport | Paired device identity | Noise XX static keys |
| Key | Key is hardware-backed | Android Key Attestation X.509 chain |
| Device | Device state, liveness | `local.attestDevice` (see [phone/attestation.md](../attestation.md)) |

## How Android Key Attestation Works

When a key is generated with an attestation challenge, Android Keystore embeds an attestation extension in the key's X.509 certificate:

1. `KeyGenParameterSpec.Builder.setAttestationChallenge(nonce)` sets the challenge
2. `keyStore.getCertificateChain(alias)` retrieves the attestation chain
3. The leaf certificate contains extension OID `1.3.6.1.4.1.11129.2.1.17`

### Certificate Chain Structure

```
[0] Leaf Certificate (attestation extension with key properties + nonce)
[1] Intermediate CA (device-specific, signs leaf)
[2] Google Hardware Attestation Root CA (signs intermediate)
```

### Verification Flow

```
xkmsd                   Phone Backend               Android Phone
   |                             |                            |
   |--- AttestKey(nonce) ------->|                            |
   |                             |--- local.attestKey ------->|
   |                             |                            |
   |                             |<-- [leaf, inter, root] ----|
   |                             |                            |
   |    Platform verifier (when configured):                  |
   |    verify chain to the configured trust store,           |
   |    nonce, minimum security level, boot state             |
   |                             |                            |
   |<-- AttestationResult -------|                            |
```

## Attestation Extension Contents (OID 1.3.6.1.4.1.11129.2.1.17)

Defined by the Android Key Attestation schema:

| Field | Description |
|-------|-------------|
| `attestationVersion` | Schema version |
| `attestationSecurityLevel` | 0=Software, 1=TEE, 2=StrongBox |
| `keymasterVersion` | Keymaster/KeyMint version |
| `keymasterSecurityLevel` | Security level of keymaster implementation |
| `attestationChallenge` | The nonce provided during key generation |
| `uniqueId` | Optional unique identifier |
| `softwareEnforced` | Key properties enforced by software |
| `teeEnforced` | Key properties enforced by hardware |

### TEE-Enforced Key Properties

| Property | Description |
|----------|-------------|
| `purpose` | Allowed operations: Sign, Decrypt, etc. |
| `algorithm` | Key algorithm: EC, RSA, AES, HMAC |
| `keySize` | Key size in bits |
| `digest` | Allowed hash algorithms |
| `origin` | Generated (in hardware) vs Imported |
| `rootOfTrust` | Verified boot state, locked bootloader |
| `osVersion` | Android OS version |
| `osPatchLevel` | Security patch level |

## JSON-RPC Protocol

### Request: `local.attestKey`

`LocalAttestKeyParams` (`xkey/pkg/pairing/protocol_local.go:236`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "local.attestKey",
  "params": {
    "keyId": "credential_abc123",
    "nonce": "<base64 challenge>"
  }
}
```

### Response

`LocalAttestKeyResult` (`protocol_local.go:242`):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "format": "android-keystore",
    "certificateChain": ["<base64 leaf>", "<base64 intermediate>", "<base64 root>"],
    "securityLevel": "strongbox",
    "nonce": "<base64 echoed challenge>"
  }
}
```

### Error Responses

Codes from `xkey/pkg/pairing/protocol.go:47`:

| Code | Constant |
|------|----------|
| -32000 | `ErrorCodeKeyNotFound` |
| -32009 | `ErrorCodeAttestFailed` |
| -32010 | `ErrorCodeAttestUnsupported` |
| -32603 | standard internal error |

## Go-Side Verification

`Backend.AttestKey` (`pkg/backend/phone/attestation.go:83`) sends
`local.attestKey` with the key's CN as `keyId` and the caller's nonce. What
happens next depends on whether the backend `Config.Attestation` is set (see
[configuration.md](configuration.md)); the xkmsd `backends.phone` section has
no attestation key, so a backend registered by xkmsd
(`RegisterPhoneBackend`, `pkg/server/backend_phone.go:58`) never has one:

- **No verifier configured** — the raw chain is returned with
  `Verified: false`.
- **Verifier configured** — the platform verifier registered for
  `attestation.platform` checks the chain. The Android verifier
  (`AndroidVerifier.VerifyAttestation`,
  `pkg/backend/phone/android/verifier.go:85`) parses the DER chain and calls
  `VerifyKeyAttestation` with the configured trust roots, the expected nonce,
  `min_security_level` and `verify_boot_state`. Any failure returns
  `ErrChainVerificationFailed`.

The Android verifier is activated by a blank import of
`github.com/jeremyhahn/go-xkms/pkg/backend/phone/android`
(`pkg/backend/phone/doc.go`).

Software-level attestations are accepted unless `min_security_level` is set
to `tee` or `strongbox` (see [security.md](security.md)).

## Attestation Result

`AttestKey` returns an `AttestationResult`
(`pkg/backend/phone/attestation.go:28`):

```go
type AttestationResult struct {
    Format           string   // e.g. "android-keystore"
    CertificateChain [][]byte // DER, leaf first
    AttestationData  []byte
    Nonce            []byte   // echoed challenge
    Backend          string   // "android-keystore-strongbox" or "android-keystore-tee"
    Verified         bool     // chain and extension verified
    PlatformData     any      // *android.KeyDescription on Android
}
```

### Security Level to Backend Mapping

`securityLevelMapping` (`pkg/backend/phone/attestation.go:56`):

| `securityLevel` | Backend String |
|-----------------|----------------|
| `tee` | `android-keystore-tee` |
| `strongbox` | `android-keystore-strongbox` |

## CLI Usage

```bash
xkmsctl key attest my-signing-key --backend phone
xkmsctl key attest my-signing-key --backend phone --nonce <base64> --output attestation.json
```

`key attest` is defined at `cmd/xkmsctl/key.go:1340`; `--nonce` (random 32
bytes when omitted) and `--output` at `key.go:1984-1985`; `--backend` is the
global flag (`cmd/xkmsctl/root.go:118`).

## Root of Trust Verification

The `rootOfTrust` field in the attestation extension provides verified boot state information:

| Field | Value | Meaning |
|-------|-------|---------|
| `verifiedBootState` | `verified` | Boot chain fully verified |
| `verifiedBootState` | `selfSigned` | Device uses user-provided root of trust |
| `verifiedBootState` | `unverified` | Boot chain not verified (unlocked bootloader) |
| `deviceLocked` | `true` | Bootloader is locked |
| `deviceLocked` | `false` | Bootloader is unlocked |

An embedder that sets `AttestationConfig.VerifyBootState` rejects devices
whose boot state is not `verified`.

## See Also

- [Phone Backend](README.md)
- [Phone Backend Configuration](configuration.md)
- [Bidirectional Attestation](../attestation.md)
- [TPM2](../../../../docs/tpm2/architecture.md)
- [Key Attestation Guide](../../../../docs/attestation-verifier/user.md)
