# Phone Backend Key Attestation

## Overview

The phone backend supports Android Key Attestation, which produces X.509 certificate chains proving that keys are stored in hardware (TEE or StrongBox). The attestation chain roots to Google's hardware attestation root CA, providing a trusted third-party guarantee of hardware backing.

## Attestation Levels

| Level | What's Proven | Mechanism |
|-------|--------------|-----------|
| Transport | Paired device identity | Noise XX static keys |
| Key | Key is hardware-backed | Android Key Attestation X.509 chain |
| Device | Device is genuine | Play Integrity API (future) |

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
   |                             |           Generate attestation chain
   |                             |           with nonce embedded in leaf
   |                             |           certificate extension
   |                             |                            |
   |                             |<-- [leaf, inter, root] ----|
   |                             |                            |
   |    Verify chain to Google root CA                        |
   |    Parse OID 1.3.6.1.4.1.11129.2.1.17                   |
   |    Verify nonce matches                                  |
   |    Check security level (TEE/StrongBox)                  |
   |    Validate key properties                               |
   |                             |                            |
   |<-- AttestationStatement ----|                            |
```

## Attestation Extension Contents (OID 1.3.6.1.4.1.11129.2.1.17)

The ASN.1-encoded extension contains:

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

The `teeEnforced` field contains the security-critical properties:

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

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "format": "android-keystore",
    "certificateChain": ["<base64 leaf>", "<base64 intermediate>", "<base64 root>"],
    "securityLevel": "strongbox",
    "nonce": "<base64 echoed challenge>",
    "attestationData": {
      "keymasterVersion": 200,
      "attestationSecurityLevel": 2,
      "purpose": ["sign"],
      "algorithm": "ec",
      "keySize": 256,
      "digest": ["sha256"],
      "origin": "generated",
      "rootOfTrust": {
        "verifiedBootKey": "<hex>",
        "deviceLocked": true,
        "verifiedBootState": "verified"
      },
      "osVersion": 150000,
      "osPatchLevel": 202501
    }
  }
}
```

### Error Responses

| Code | Name | Description |
|------|------|-------------|
| -32000 | KeyNotFound | Credential does not exist |
| -32008 | AttestationUnavailable | Device does not support attestation |
| -32603 | InternalError | Keystore or hardware failure |

## Go-Side Verification

The Go backend (`pkg/backend/phone/attestation.go`) verifies attestation in five steps:

### Step 1: Certificate Chain Validation

Verify the chain from the leaf certificate through the intermediate to Google's hardware attestation root CA. The root certificate is embedded in the Go binary for offline verification.

```go
// Google Hardware Attestation Root CA is the trust anchor
// for all Android hardware attestation chains
roots := x509.NewCertPool()
roots.AddCert(googleHardwareAttestationRoot)

opts := x509.VerifyOptions{
    Roots:         roots,
    Intermediates: intermediatePool,
    KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
}

_, err := leafCert.Verify(opts)
```

### Step 2: Parse Attestation Extension

Extract the attestation data from the leaf certificate's extension with OID `1.3.6.1.4.1.11129.2.1.17`.

```go
var attestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

for _, ext := range leafCert.Extensions {
    if ext.Id.Equal(attestationOID) {
        // Parse ASN.1-encoded attestation extension
        attestation, err := parseAttestationExtension(ext.Value)
    }
}
```

### Step 3: Nonce Verification

Ensure `attestationChallenge` in the extension matches the nonce that was sent in the attestation request. This prevents replay attacks.

```go
if !bytes.Equal(attestation.Challenge, expectedNonce) {
    return ErrAttestationNonceMismatch
}
```

### Step 4: Security Level Check

Verify that `attestationSecurityLevel` is TEE (1) or StrongBox (2). Software-level attestation (0) is rejected in production because it does not prove hardware backing.

```go
if attestation.SecurityLevel < SecurityLevelTEE {
    return ErrAttestationNotHardwareBacked
}
```

### Step 5: Key Properties Validation

Confirm that the key algorithm, purpose, and key size match the expected values for the credential.

```go
if attestation.Algorithm != expectedAlgorithm {
    return ErrAttestationAlgorithmMismatch
}
if attestation.KeySize != expectedKeySize {
    return ErrAttestationKeySizeMismatch
}
```

## Attestation Statement

The phone backend returns an `attestation.AttestationStatement` (from `pkg/attestation/types.go`):

```go
type AttestationStatement struct {
    Format           string              // "android-keystore"
    Signature        []byte              // Not used (chain-based attestation)
    CertificateChain []*x509.Certificate // [leaf, intermediate, root]
    Nonce            []byte              // Challenge nonce
    Backend          string              // "android-keystore-tee" or "android-keystore-strongbox"
    AttestationData  interface{}         // Parsed attestation extension data
}
```

### Security Level to Backend Mapping

| Security Level | Value | Backend String |
|---------------|-------|----------------|
| Software | 0 | Rejected (not hardware-backed) |
| TEE | 1 | `android-keystore-tee` |
| StrongBox | 2 | `android-keystore-strongbox` |

## CLI Usage

### Attest a Phone-Backed Key

```bash
xkmsctl attest --backend phone --key my-signing-key
```

Output:

```
Attestation Format: android-keystore
Security Level: StrongBox
Certificate Chain: 3 certificates
Chain Valid: true (verified to Google root CA)
Key Algorithm: EC P-256
Key Purpose: Sign
Hardware Origin: Generated in hardware
Boot State: Verified, device locked
OS Version: Android 15, patch 2025-01
```

### Verbose Attestation Output

```bash
xkmsctl attest --backend phone --key my-signing-key --verbose
```

Output:

```
Attestation Format: android-keystore
Security Level: StrongBox (level 2)
Keymaster Version: 200

Certificate Chain:
  [0] Leaf:         CN=Android Keystore Key
      Serial:       1234567890
      Not Before:   2025-01-15 10:30:00 UTC
      Not After:    2035-01-15 10:30:00 UTC
  [1] Intermediate: CN=Google Hardware Attestation Intermediate
      Serial:       9876543210
  [2] Root:         CN=Google Hardware Attestation Root
      Serial:       1

Chain Valid: true

Key Properties (TEE-enforced):
  Algorithm:  EC P-256
  Key Size:   256 bits
  Purpose:    Sign
  Digest:     SHA-256
  Origin:     Generated in hardware

Root of Trust:
  Verified Boot Key: a1b2c3d4...
  Device Locked:     true
  Boot State:        Verified

OS Info:
  Version:     Android 15 (150000)
  Patch Level: 2025-01
```

## Backends That Do Not Support Attestation

The `Capabilities` struct includes an `Attestation` field. Backends that do not support attestation return `backend.ErrOperationNotSupported` from `AttestKey()`.

| Backend | Attestation | Format |
|---------|------------|--------|
| Phone | Yes | `android-keystore` |
| TPM2 | Yes | `tpm2` |
| PKCS#11 | Yes | `pkcs11` |
| Software | No | N/A |
| AWS KMS | No | N/A |
| GCP KMS | No | N/A |
| Azure KV | No | N/A |

## Root of Trust Verification

The `rootOfTrust` field in the attestation extension provides verified boot state information:

| Field | Value | Meaning |
|-------|-------|---------|
| `verifiedBootState` | `verified` | Boot chain fully verified |
| `verifiedBootState` | `selfSigned` | Device uses user-provided root of trust |
| `verifiedBootState` | `unverified` | Boot chain not verified (unlocked bootloader) |
| `deviceLocked` | `true` | Bootloader is locked |
| `deviceLocked` | `false` | Bootloader is unlocked |

Production deployments should require `verifiedBootState == "verified"` and `deviceLocked == true` to ensure the device has not been tampered with.

## See Also

- [Phone Backend Architecture](../phone/)
- [Phone Backend Configuration](configuration.md)
- [Bidirectional Attestation](../../xkey/phone-backend.md)
- [TPM2 Attestation](../tpm2.md)
- [Key Attestation Guide](../../attestation/README.md)
