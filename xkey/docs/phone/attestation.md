# Bidirectional Attestation

## Overview

Both devices can attest the hardware backing of their keys. This enables mutual trust verification: the laptop verifies that phone keys are in genuine secure hardware, and the phone verifies that laptop keys are backed by real TPM2 or HSM hardware.

| Direction | Method | Attestation Type |
|-----------|--------|-----------------|
| Phone to Laptop | `local.attestKey` | Android Key Attestation (X.509 chain to Google root) |
| Laptop to Phone | `remote.attestKey` | TPM2 Certify, PKCS#11 chain, or backend-specific |

## Phone to Laptop Attestation

Uses Android Key Attestation as defined in the Android Keystore specification.

### Certificate Chain

The phone returns an X.509 certificate chain:

```
Leaf Certificate (key attestation)
  |
  +-- Intermediate CA (device manufacturer)
       |
       +-- Google Hardware Attestation Root CA
```

The leaf certificate contains the attestation extension at OID `1.3.6.1.4.1.11129.2.1.17`, which encodes the key properties and device security state.

### Attestation Extension Fields

| Field | Description |
|-------|-------------|
| `attestationVersion` | Schema version (1, 2, 3, 4, 100, 200) |
| `attestationSecurityLevel` | `SOFTWARE`, `TRUSTED_ENVIRONMENT`, or `STRONG_BOX` |
| `keymasterSecurityLevel` | Security level of the keymaster implementation |
| `attestationChallenge` | Nonce provided by the verifier |
| `uniqueId` | Optional unique device identifier |
| `softwareEnforced` | Key properties enforced by software |
| `teeEnforced` | Key properties enforced by TEE/StrongBox hardware |

### Verification Flow

```
Laptop                                    Phone
  |                                         |
  | Generate random nonce (32 bytes)        |
  |                                         |
  |-- local.attestKey -------------------->|
  |   {keyId:"sig-key",                    |
  |    challenge:"base64(nonce)"}          |
  |                                         |
  |                        Phone generates  |
  |                        attestation with |
  |                        challenge bound  |
  |                        to the key       |
  |                                         |
  |<-- result: {certificateChain:[...], ---|
  |     securityLevel:"strongbox",         |
  |     attestationVersion: 200}           |
  |                                         |
  | 1. Parse leaf certificate               |
  | 2. Verify chain to Google Root CA       |
  | 3. Check attestation extension OID      |
  | 4. Verify challenge matches nonce       |
  | 5. Check securityLevel >= TEE           |
  | 6. Verify key properties match          |
  |    expected algorithm/purpose           |
  | 7. Optionally check boot state          |
  |    (verified boot, patch level)         |
  |                                         |
```

### Go-Side Verification

```go
func VerifyPhoneAttestation(chain []*x509.Certificate, nonce []byte) error {
    // 1. Verify chain to Google Hardware Attestation Root
    roots := x509.NewCertPool()
    roots.AddCert(googleHardwareAttestationRoot)
    opts := x509.VerifyOptions{Roots: roots}
    if _, err := chain[0].Verify(opts); err != nil {
        return ErrChainVerificationFailed
    }

    // 2. Parse attestation extension
    ext := findExtension(chain[0], attestationOID)
    if ext == nil {
        return ErrAttestationExtensionMissing
    }

    var attestation KeyAttestationExtension
    if err := asn1.Unmarshal(ext.Value, &attestation); err != nil {
        return ErrAttestationParseFailed
    }

    // 3. Verify nonce
    if !bytes.Equal(attestation.Challenge, nonce) {
        return ErrNonceMismatch
    }

    // 4. Check security level
    if attestation.SecurityLevel < SecurityLevelTEE {
        return ErrInsufficientSecurityLevel
    }

    return nil
}
```

---

## Laptop to Phone Attestation

Uses xkmsd's `AttestingBackend.AttestKey()` interface. The attestation format depends on the backend type.

### TPM2 Backend

The TPM2 backend provides hardware attestation using `TPM2_Certify`:

```
Attestation Key (AK)
  |
  +-- Certifies target key via TPM2_Certify
  |
  +-- AK Certificate Chain
       |
       +-- EK Certificate (from TPM manufacturer)
            |
            +-- TPM Manufacturer Root CA
```

**Attestation data includes:**

| Field | Description |
|-------|-------------|
| `certifyInfo` | TPM2B_ATTEST structure (TPMS_ATTEST) |
| `signature` | Signature over certifyInfo by AK |
| `akCertificate` | AK certificate chain |
| `ekCertificate` | Endorsement Key certificate |
| `qualifiedName` | TPM qualified name of the key |
| `pcrValues` | Optional PCR values for platform state |

### PKCS#11 Backend

HSM backends provide attestation via certificate chains from the HSM vendor:

```
Key Certificate (issued by HSM)
  |
  +-- HSM Intermediate CA
       |
       +-- HSM Vendor Root CA
```

Attestation capabilities vary by HSM. Some HSMs (YubiKey, SmartCard-HSM) support key attestation certificates; others only provide basic certificate chains.

### Software Backend

The software backend does not support hardware attestation. Calling `remote.attestKey` against a software backend returns error `-32020` (AttestationUnsupported).

### Verification Flow (Phone Side)

```
Phone                                     Laptop
  |                                         |
  | Generate random nonce (32 bytes)        |
  |                                         |
  |-- remote.attestKey ------------------->|
  |   {keyId:"tpm-key",                    |
  |    challenge:"base64(nonce)"}          |
  |                                         |
  |                     Laptop calls        |
  |                     xkmsd           |
  |                     AttestKey()         |
  |                                         |
  |<-- result: {format:"tpm2",          ---|
  |     attestation:"base64(...)",         |
  |     certificateChain:[...]}            |
  |                                         |
  | 1. Check format field                   |
  | 2. Parse attestation data               |
  | 3. For TPM2:                            |
  |    a. Parse TPMS_ATTEST structure       |
  |    b. Verify signature with AK          |
  |    c. Verify AK cert chain to EK        |
  |    d. Check nonce in certifyInfo        |
  |    e. Verify key name matches           |
  | 4. For PKCS#11:                         |
  |    a. Verify certificate chain          |
  |    b. Check key properties              |
  |                                         |
```

---

## Attestation Comparison

| Property | Android (Phone) | TPM2 (Laptop) | PKCS#11 (Laptop) | Software (Laptop) |
|----------|----------------|---------------|-------------------|--------------------|
| Format | X.509 chain | TPM2_Certify | Certificate chain | Not supported |
| Root of trust | Google Root CA | EK certificate | HSM vendor CA | N/A |
| Security level | TEE / StrongBox | TPM hardware | HSM hardware | N/A |
| Nonce support | Yes | Yes | Varies by HSM | N/A |
| Boot state | Verified boot, patch level | PCR values | No | N/A |
| Key binding | Key properties in extension | Key name in certifyInfo | Key in certificate | N/A |
| Revocation | Google CRL | Manufacturer CRL | HSM vendor CRL | N/A |

## Trust Levels

Applications can define minimum trust levels for cross-device operations:

| Level | Requirement |
|-------|-------------|
| `none` | No attestation required |
| `any-hardware` | Any hardware-backed attestation (TEE, TPM, HSM) |
| `strongbox-or-tpm` | StrongBox (phone) or TPM2 (laptop) |
| `verified` | Full chain verification to known root CA |

Configuration:

```yaml
phone:
  attestation:
    minimum_trust: "any-hardware"
    verify_boot_state: true
    max_patch_age_days: 90
```

---

## Device Attestation (Future)

Beyond key attestation, device-level attestation verifies the overall device integrity.

### Phone: Play Integrity API

- Verifies device integrity (not rooted, genuine ROM)
- Returns signed verdict from Google servers
- Method: `local.attestDevice`

### Laptop: TPM2 Quote

- TPM2_Quote over PCR values proves platform state
- Verifies secure boot chain, kernel integrity
- Method: `remote.attestDevice`

These methods are planned for a future release and are not yet part of the protocol.

---

## See Also

- [Protocol Specification](protocol.md) - Full method reference
- [Bidirectional Key Sharing](bidirectional.md) - Sharing policies and trust
- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) - Android documentation
