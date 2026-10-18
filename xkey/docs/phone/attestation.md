# Bidirectional Attestation

> **Status: REFERENCE** · Last verified: 2026-10-13
> Background for phone attestation; superseded by [phone/architecture.md](architecture.md) and [phone-hsm/architecture.md](../phone-hsm/architecture.md). Where they disagree, the feature folders win.

## Overview

Both devices can attest the hardware backing of their keys. This enables mutual trust verification: the laptop verifies that phone keys are in genuine secure hardware, and the phone verifies that laptop keys are backed by real TPM2 or HSM hardware.

| Direction | Method | Attestation Type |
|-----------|--------|-----------------|
| Phone to Laptop | `local.attestDevice`, `local.attestKey` | Android Key Attestation (X.509 chain to Google root) |
| Laptop to Phone | `remote.attestKey`, `remote.attestDevice` | Backend-specific (TPM2, PKCS#11) |

## Phone to Laptop Attestation

Uses Android Key Attestation as defined in the Android Keystore specification.

The desktop attests a phone with `local.attestDevice` everywhere: pairing,
reconnect, and the manual "Attest Device" action all go through the single
decision in `xkey/pkg/attestation` — `AttestOverSession` and
`VerifyDeviceAttestation` (`xkey/pkg/attestation/device.go`). The hardware
bar — chain, security level, boot state, key origin and application — is the
SDK's `xkms.VerifyAndroidDeviceKey` (`pkg/attestation/android_device.go`);
xkey adds only the pairing protocol's checks. A certificate's attestation challenge is fixed for the
life of a persistent key, so comparing it with a nonce proves nothing after
first use; the phone therefore also signs a live transcript covering the
nonce, a purpose string (`"pair"` or `"reattest"`) and a channel binding
derived from the current Noise session. `local.attestKey` still exists for
one-off key-only attestation without that liveness commitment; device trust
decisions are not made on it.

### Certificate Chain

The phone returns an X.509 certificate chain:

```
Leaf Certificate (key attestation)
  |
  +-- Intermediate CA (device manufacturer)
       |
       +-- Google Hardware Attestation Root CA
```

The leaf certificate contains the attestation extension at OID `1.3.6.1.4.1.11129.2.1.17` (read by go-xkms `pkg/attestation/android/extension.go:647`, `VerifyKeyAttestation`, which xkey reaches through `sdk/go` as `VerifyAndroidKeyAttestation`), which encodes the key properties and device security state.

### Attestation Extension Fields

Defined by the Android Key Attestation schema:

| Field | Description |
|-------|-------------|
| `attestationVersion` | Schema version |
| `attestationSecurityLevel` | `SOFTWARE`, `TRUSTED_ENVIRONMENT`, or `STRONG_BOX` |
| `keymasterSecurityLevel` | Security level of the keymaster implementation |
| `attestationChallenge` | Challenge set when the key was generated |
| `uniqueId` | Optional unique device identifier |
| `softwareEnforced` | Key properties enforced by software |
| `teeEnforced` | Key properties enforced by TEE/StrongBox hardware |

### Key-only attestation (`local.attestKey`)

```
Laptop                                    Phone
  |                                         |
  |-- local.attestKey -------------------->|
  |   {keyId:"sig-key",                    |
  |    nonce:"base64(nonce)"}              |
  |                                         |
  |<-- result: {format:"android-keystore",-|
  |     certificateChain:[...],            |
  |     securityLevel:"strongbox",         |
  |     nonce:"base64(nonce)"}             |
```

Params and result are `LocalAttestKeyParams` / `LocalAttestKeyResult`
(`pkg/pairingproto/protocol_local.go:236`, `:242`).

---

## Laptop to Phone Attestation

The phone calls `remote.attestKey` (`RemoteAttestKeyParams`:
`backend`, `keyId`, `nonce`; `pkg/pairingproto/protocol_remote.go:233`). The
laptop bridge forwards it to xkmsd, and the result (`RemoteAttestKeyResult`,
`protocol_remote.go:240`) carries `format`, `certificateChain`,
`attestationData` and the echoed `nonce`. The attestation format depends on
the backend type.

### TPM2 Backend

The TPM2 backend attests with an Attestation Key whose certificate chains to
the TPM's Endorsement Key certificate and manufacturer root:

```
Attestation Key (AK)
  |
  +-- Certifies target key
  |
  +-- AK Certificate Chain
       |
       +-- EK Certificate (from TPM manufacturer)
            |
            +-- TPM Manufacturer Root CA
```

### PKCS#11 Backend

HSM backends provide attestation via certificate chains from the HSM vendor.
Attestation capabilities vary by HSM; some support key attestation
certificates, others only provide basic certificate chains.

### Unsupported backends

A backend without attestation (for example the software backend) fails
`remote.attestKey` with `-32010` `ErrorCodeAttestUnsupported`
(`pkg/pairingproto/protocol.go:47`; mapped in `xkey/pkg/pairing/bridge.go:1021`).

### Verification Flow (Phone Side)

```
Phone                                     Laptop
  |                                         |
  |-- remote.attestKey ------------------->|
  |   {backend:"tpm2", keyId:"tpm-key",    |
  |    nonce:"base64(nonce)"}              |
  |                                         |
  |                     Laptop calls        |
  |                     xkmsd AttestKey()   |
  |                                         |
  |<-- result: {format:"tpm2",          ---|
  |     certificateChain:[...],            |
  |     attestationData:"base64(...)",     |
  |     nonce:"base64(nonce)"}             |
  |                                         |
  | 1. Check format field                   |
  | 2. Verify certificate chain             |
  | 3. Check nonce and key binding in       |
  |    attestationData                      |
```

---

## Attestation Comparison

| Property | Android (Phone) | TPM2 (Laptop) | PKCS#11 (Laptop) | Software (Laptop) |
|----------|----------------|---------------|-------------------|--------------------|
| Format | X.509 chain | TPM2 attestation | Certificate chain | Not supported |
| Root of trust | Google Root CA | EK certificate | HSM vendor CA | N/A |
| Security level | TEE / StrongBox | TPM hardware | HSM hardware | N/A |
| Boot state | Verified boot, patch level | PCR values | No | N/A |

## Per-device attestation policy

Each paired device record can pin its later attestations
(`PairedDevice.AttestationPolicy`, `xkey/pkg/pairing/device.go:113`;
`PairedDeviceAttestationPolicy`, `device.go:137`):

```yaml
attestation_policy:
  enabled: true
  boot_hash: ""
  boot_key_hash: ""
  boot_state: ""
  device_locked: true
  min_security_level: ""
```

The `phone.attestation_policy` key of the xkey config is a single string
(`PhoneConfig.AttestationPolicy`, `xkey/pkg/config/config.go:127`).

---

## Device Attestation

Beyond key attestation, device-level attestation verifies the overall device
state:

- Phone: `local.attestDevice` (`pkg/pairingproto/protocol_local.go`).
- Laptop: `remote.attestDevice` and `remote.getAttestationQuote`, a TPM2 quote
  over PCR values (`pkg/pairingproto/protocol_remote.go:32`, `:62`).

---

## See Also

- [Protocol Specification](protocol.md) - Full method reference
- [Bidirectional Key Sharing](bidirectional.md) - Sharing policies and trust
- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) - Android documentation
