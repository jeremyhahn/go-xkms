# PIV Implementation Roadmap

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: open plan for PIV-I; each phase is marked done or open against the code. For PIV as built, the [piv feature folder](../piv/architecture.md) is normative.

xkey targets PIV-I (PIV-Interoperable, FIPS 201-3 / NIST SP 800-73-4) to enable physical access control and mTLS authentication from both desktop and mobile devices. The goal is for every PIV key to live on FIPS 140-2/3 validated hardware (PKCS#11 HSMs, TPM2, AWS/Azure/GCP cloud KMS).

## Federal Compliance Position

### go-xkms is a platform, not a credential

go-xkms does not need FBCA cross-certification. Like Microsoft AD CS or EJBCA, go-xkms is the **certificate generation engine**. The deploying organization gets their CA cross-certified — not the software. AD CS has no FBCA cross-cert. EJBCA has no FBCA cross-cert. Neither does go-xkms need one.

**What go-xkms provides** (PIV-I profiles are still open, see Phase 1): PIV-I compliant certificate profiles, CRL generation, OCSP, key management on FIPS-validated backends, certificate lifecycle management.

**What the deploying organization provides**: Certificate Policy (CP), Certification Practice Statement (CPS), trust chain cross-certification, identity proofing operations, compliance audits.

### Trust chain options for deploying organizations

| Path | Cost | Timeline | Description |
|------|------|----------|-------------|
| CertiPath bridge | ~$100K-$300K/year | Months | Commercial bridge CA cross-certified with FBCA |
| IdenTrust | Varies | Months | Already cross-certified with FBCA; org subordinates under IdenTrust |
| Direct FBCA | $500K-$1M+ | 12-24 months | Direct cross-certification with Federal Bridge CA |

### FIPS 140 coverage

The hardware backends and their FIPS 140-2/3 validation levels:

| Backend | FIPS Level | Private Key Protection |
|---------|-----------|----------------------|
| PKCS#11 (Luna, nCipher, YubiHSM) | Level 2/3 | Keys never leave HSM |
| TPM2 | Level 1/2 | Keys bound to TPM |
| AWS KMS (CloudHSM) | Level 3 | Keys in cloud HSM |
| Azure Key Vault (Managed HSM) | Level 3 | Keys in cloud HSM |
| GCP KMS (Cloud HSM) | Level 3 | Keys in cloud HSM |

Target: CA private keys, PIV slot keys, and content signing keys all reside in validated hardware. Today a software PIV key generator also exists (`NewSoftwarePIVKeyGenerator`, `pkg/xkms/piv_keygen_software.go`), so this holds only when a hardware backend is configured.

### What works today for federal logical access

| Requirement | Capability | Status |
|-------------|-----------|--------|
| Phishing-resistant MFA (OMB M-22-09) | FIDO2/CTAP2 (`pkg/fido2/`) | Done |
| mTLS client auth | PKCS#11 module + PIV certificates (`pkg/auth/pkcs11_tls.go:236`) | Done |
| PIV certificate management | All slots, file/TPM2/PKCS#11 storage (`pkg/pivcert/`) | Done |
| CA with PIV-I certificate profiles | `pkg/ca/` has no PIV profile or PIV OIDs | Open |
| CRL generation | `pkg/ca/revocation.go` | Done |
| OCSP responder | `OCSPResponder` (`pkg/ca/ocsp.go:107`) | Done |
| Certificate chain verification | `pkg/ca/verification.go` | Done |

## Current State

### What's implemented

**CA and Certificate Infrastructure** (`pkg/ca/`):
- CA core (`ca.go`), issuance (`issuance.go`), CSR creation (`csr.go`), profiles (`profiles.go`)
- CRL generation (`revocation.go`) and certificate verification (`verification.go`)
- TLS helpers (`tls.go`)
- OCSP responder: `NewOCSPResponder` / `OCSPResponder.HandleRequest` (`ocsp.go:141`)

**PKCS#11 PIV Bridge** (`pkg/pkcs11/module/`):
- The `PKCS11Transport` interface (`transport.go:47`) carries the PIV methods `ListPIVSlots`, `GetPIVCertificate`, `GeneratePIVKey`, `StorePIVCertificate`, `DeletePIVCertificate`, `ImportPIVCertificate`, `ExportPIVCertificate`, `GeneratePIVCSR`
- `module_piv.go` creates PKCS#11 objects (CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY) per slot (`LoadPIVObjects`)

**mTLS via PKCS#11** (`pkg/auth/pkcs11_tls.go`):
- `NewPKCS11TLSConfig()` (`pkcs11_tls.go:236`) creates a `tls.Config` for PKCS#11-backed client auth
- The `libxkms_pkcs11.so` shared library is built by the root `Makefile`

**PIV Certificate Storage** (`pkg/pivcert/`):
- Slots 9A, 9C, 9D, 9E, F9 and retired slots 82-95 (`pivcert.go`)
- File, TPM2, and PKCS#11 storage backends (`pkg/pivcert/{file,tpm2,pkcs11}`)

**xkey Desktop PIV CLI**: see the [piv feature folder](../piv/cli.md).

**Virtual CCID with a partial APDU engine** (`xkey/pkg/ccid/`):
- `PKCS11Bridge` (`bridge.go`) selects the PIV or OpenPGP AID and dispatches SELECT, VERIFY, PSO, READ BINARY, GENERATE ASYMMETRIC and GET DATA (`apduHandlers`, `bridge.go:162`) onto PKCS#11

**xkey-android**: lives in a separate repository; its PIV state is not verified here.

### What's missing

1. **PIV-I certificate profile compliance** — no PIV profile, PIV-I policy OIDs, UUID SAN encoding, FASC-N encoding, or EKU criticality handling in `pkg/ca/`
2. **PIV data objects** — no CHUID, CCC, Discovery Object, or Security Object construction
3. **Content signing certificate** — no profile or workflow for signing PIV data objects
4. **Key escrow for slot 9D** — `pkg/escrow/` exists but has no PIV slot 9D workflow
5. **Full PIV APDU engine** — the CCID bridge has no GENERAL AUTHENTICATE or PUT DATA handler, and there is no `pkg/piv/`
6. **Android HCE** — not in this repository

## PIV-I Certificate Profile Compliance

### Policy OIDs

These OIDs must be added to `pkg/ca/profiles.go`:

```go
// PIV-I Policy OIDs (id-fpki-certpcy arc: 2.16.840.1.101.3.2.1.3)
var (
    // OIDPIVIAuthentication is the PIV-I Authentication policy.
    // OID: 2.16.840.1.101.3.2.1.3.18
    OIDPIVIAuthentication = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 18}

    // OIDPIVICardAuth is the PIV-I Card Authentication policy.
    // OID: 2.16.840.1.101.3.2.1.3.19
    OIDPIVICardAuth = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 19}

    // OIDPIVIContentSigning is the PIV-I Content Signing policy.
    // OID: 2.16.840.1.101.3.2.1.3.20
    OIDPIVIContentSigning = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 20}

    // OIDPIVContentSigningEKU is the PIV Content Signing EKU.
    // OID: 2.16.840.1.101.3.6.7
    OIDPIVContentSigningEKU = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 7}

    // OIDPIVNACIIndicator is the NACI background investigation indicator.
    // OID: 2.16.840.1.101.3.6.9.1
    OIDPIVNACIIndicator = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 9, 1}
)
```

### Certificate profiles per slot

#### Slot 9A — PIV Authentication

| Field | Value |
|-------|-------|
| Key Usage | `digitalSignature` (CRITICAL) |
| Extended Key Usage | `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2), `id-msScLogin` (1.3.6.1.4.1.311.20.2.2) — NOT critical |
| Certificate Policy | `id-fpki-certpcy-pivi-hardware` (2.16.840.1.101.3.2.1.3.18) |
| SAN | `uniformResourceIdentifier = urn:uuid:<UUID>`, optional `rfc822Name` |
| AIA | `id-ad-caIssuers` (HTTP URL to issuer cert .p7c), `id-ad-ocsp` (OCSP responder URL) |
| CDP | HTTP URL to CRL |
| SKI/AKI | Required |
| Basic Constraints | Omitted (end-entity) |
| Max Validity | 3 years (1095 days) |
| PIN Behavior | PIN once per session |

#### Slot 9C — Digital Signature

| Field | Value |
|-------|-------|
| Key Usage | `digitalSignature`, `nonRepudiation` (CRITICAL) |
| Extended Key Usage | `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4) — optional, NOT critical |
| Certificate Policy | `id-fpki-common-hardware` (2.16.840.1.101.3.2.1.3.7) |
| SAN | `rfc822Name` (required for S/MIME), `uniformResourceIdentifier = urn:uuid:<UUID>` |
| AIA/CDP/SKI/AKI | Same as 9A |
| Max Validity | 3 years |
| PIN Behavior | PIN required before EVERY signing operation |

#### Slot 9D — Key Management

| Field | Value |
|-------|-------|
| Key Usage | `keyEncipherment` (RSA) OR `keyAgreement` (ECC) — never both (CRITICAL) |
| Extended Key Usage | `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4) — NOT critical |
| Certificate Policy | `id-fpki-common-hardware` (2.16.840.1.101.3.2.1.3.7) |
| SAN | `rfc822Name`, `uniformResourceIdentifier = urn:uuid:<UUID>` |
| AIA/CDP/SKI/AKI | Same as 9A |
| Max Validity | 3 years |
| Key Escrow | Private key archival permitted (only slot where this is allowed) |
| PIN Behavior | PIN once per session |

#### Slot 9E — Card Authentication

| Field | Value |
|-------|-------|
| Key Usage | `digitalSignature` (CRITICAL) |
| Extended Key Usage | `id-piv-cardAuth` (2.16.840.1.101.3.6.8), `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2) — **CRITICAL** |
| Certificate Policy | `id-fpki-certpcy-pivi-cardAuth` (2.16.840.1.101.3.2.1.3.19) |
| SAN | `uniformResourceIdentifier = urn:uuid:<UUID>` — **CRITICAL if Subject DN empty** |
| Subject DN | Organization name or card identifier (NOT cardholder name) |
| AIA/CDP/SKI/AKI | Same as 9A |
| Max Validity | 3 years |
| Preferred Algorithm | ECC P-256 (contactless performance) |
| PIN Behavior | No PIN ever |

#### Content Signing Certificate

| Field | Value |
|-------|-------|
| Key Usage | `digitalSignature` (CRITICAL) |
| Extended Key Usage | `id-PIV-content-signing` (2.16.840.1.101.3.6.7) — **CRITICAL** |
| Certificate Policy | `id-fpki-certpcy-pivi-contentSigning` (2.16.840.1.101.3.2.1.3.20) |
| Subject DN | Card Management System identifier |
| AIA/CDP/SKI/AKI | Same as 9A |
| Max Validity | 9 years (must outlive all cards it signs) |
| Key Location | CA HSM, NOT on card |

### UUID encoding in SAN

All certificates for a single card must use the same UUID. Encoded as a URI in the `uniformResourceIdentifier` field of SubjectAltName:

```
urn:uuid:<lowercase-hex-with-hyphens>
Example: urn:uuid:3e6a5c02-8d4e-4f1b-9c7a-2b5d8e1f4a6c
```

UUID version 4 (random). The same UUID appears in certificates AND the CHUID.

### Cryptographic algorithms (SP 800-78-5)

| Algorithm | Key Sizes | Notes |
|-----------|----------|-------|
| RSA | 2048, 3072 | 3072+ required after 2031 |
| ECDSA | P-256, P-384 | P-256 preferred for 9E (contactless) |
| EdDSA | Ed25519, Ed448 | Under FIPS 186-5, future consideration |
| SHA | SHA-256, SHA-384 | SHA-1 prohibited |

### AIA and CDP requirements

All PIV-I certificates must include:

```
Authority Information Access:
  CA Issuers: http://<domain>/certs/<issuer>.p7c    (PKCS#7 format)
  OCSP:       http://<domain>/ocsp                   (OCSP responder URL)

CRL Distribution Points:
  Full Name:  http://<domain>/crl/<issuer>.crl       (DER-encoded CRL)
```

CRLs must be published at least every 18 hours. OCSP responses must be current.

## PIV-I Data Objects

### CHUID (Card Holder Unique Identifier)

Container tag: `5FC102`. The primary identification object for PACS readers.

```
Tag    Len  Description                  PIV-I Value
0x30   25   FASC-N                       All 9s (BCD encoded):
                                         D4E739DA739CED39CE739DA6739CED39
                                         CE739DA67368 5821CB
0x34   16   UUID (GUID)                  16 bytes binary, big-endian
                                         Same UUID as certificate SANs
0x35   8    Expiration Date              ASCII YYYYMMDD (e.g., "20280214")
0x36   1    Org Identifier Type          0x01 (UUID present)
0x3E   var  Issuer Asymmetric Signature  CMS SignedData over preceding TLVs
                                         Signed with Content Signing key
0xFE   0    Error Detection Code         Empty
```

### Security Object

Container tag: `5FC106`. CMS SignedData containing SHA-256 hashes of all data objects on the card. Uses ICAO LDS Security Object format (OID: `2.23.136.1.1.1`).

```
ContentInfo (id-signedData 1.2.840.113549.1.7.2)
  SignedData:
    version: 3
    digestAlgorithms: { SHA-256 }
    encapContentInfo:
      eContentType: id-icao-ldsSecurityObject (2.23.136.1.1.1)
      eContent: LDSSecurityObject
        version: 0
        hashAlgorithm: SHA-256
        dataGroupHashValues:
          { dataGroupNumber: 1, hash: SHA-256(CHUID) }
          { dataGroupNumber: 6, hash: SHA-256(9A cert) }
          { dataGroupNumber: 7, hash: SHA-256(9C cert) }
          { dataGroupNumber: 8, hash: SHA-256(9D cert) }
          { dataGroupNumber: 9, hash: SHA-256(9E cert) }
    certificates: [ Content Signing Certificate ]
    signerInfos: [ signed with Content Signing key ]
```

### Discovery Object

Container tag: `7E`. Advertises PIV AID and PIN policy.

```
7E 12
  4F 0B A000000308000010000100          PIV AID (11 bytes)
  5F2F 02 4010                          PIN policy:
                                          0x40 = App PIN satisfies ACRs
                                          0x10 = App PIN is primary
```

### CCC (Card Capability Container)

Container tag: `5FC107`. Card identification and capabilities.

```
F0 15  Card Identifier (21 bytes): RID + card type + unique ID
F1 01  Container version: 01
F2 01  Grammar version: 01
F3 00  Applications CardURL: empty
F4 01  PKCS#15: 00 (not present)
F5 01  Data model: 10 (PIV)
F6-FE  Optional fields: empty
```

## Architecture

```
+---------------------------------------------------+
|              Physical Access Reader                |
|          (NFC / Contact smart card)                |
+---------------------------------------------------+
          |  ISO 7816 APDUs
          v
+---------+------------------------------------------+
|                                                    |
|  Desktop (xkey)           Mobile (xkey-android)    |
|  +-----------------+      +--------------------+   |
|  | Virtual CCID    |      | Android HCE        |   |
|  | (USB/UHID)      |      | (NFC contactless)  |   |
|  | xkey/pkg/ccid/  |      | HostApduService    |   |
|  +-----------------+      +--------------------+   |
|          |                         |               |
|          v                         v               |
|  +---------------------------------------------+  |
|  |         PIV APDU Engine (shared)             |  |
|  |         pkg/piv/                             |  |
|  |                                              |  |
|  |  SELECT AID  -> route to PIV applet          |  |
|  |  GET DATA    -> return CHUID, CCC, certs     |  |
|  |  VERIFY      -> PIN validation               |  |
|  |  GEN AUTH    -> challenge-response signing    |  |
|  |  PUT DATA    -> cert/data object import      |  |
|  +---------------------------------------------+  |
|          |                         |               |
|          v                         v               |
|  +---------------------------------------------+  |
|  |         Key + Certificate Storage            |  |
|  |  Desktop: TPM2 / PKCS#11 HSM / Software     |  |
|  |  Android: StrongBox / AndroidKeystore        |  |
|  |  All backends: FIPS 140-2/3 validated        |  |
|  +---------------------------------------------+  |
|          |                                         |
|          v                                         |
|  +---------------------------------------------+  |
|  |         CA Infrastructure                    |  |
|  |  pkg/ca/ — Certificate issuance, CRL, OCSP  |  |
|  |  PIV-I profiles, content signing, key escrow |  |
|  +---------------------------------------------+  |
+---------------------------------------------------+
```

## Implementation Phases

### Phase 1: PIV-I Certificate Profile Compliance — Open

Add PIV-I profiles to `pkg/ca/profiles.go`; `pkg/ca/` has no PIV profile or PIV OID today.

**1a. Add PIV-I policy OIDs** (`pkg/ca/profiles.go`):
- Add `OIDPIVIAuthentication`, `OIDPIVICardAuth`, `OIDPIVIContentSigning`
- Add `OIDPIVContentSigningEKU`, `OIDPIVNACIIndicator`
- Update each profile to assert correct policy OID in Certificate Policies extension

**1b. UUID SAN encoding** (`pkg/ca/`):
- Add `WithUUID(uuid string)` profile option
- Encode as `uniformResourceIdentifier = urn:uuid:<uuid>` in SAN
- Ensure all 4 slot certs for same card share the same UUID

**1c. EKU criticality** (`pkg/ca/profiles.go`):
- Slot 9E: EKU must be CRITICAL
- Content Signing: EKU must be CRITICAL
- Slots 9A, 9C, 9D: EKU NOT critical

**1d. Content signing certificate profile** (`pkg/ca/profiles.go`):
- New profile `piv-content-signing`
- EKU: `id-PIV-content-signing` (2.16.840.1.101.3.6.7), CRITICAL
- Policy: `id-fpki-certpcy-pivi-contentSigning` (2.16.840.1.101.3.2.1.3.20)
- Max validity: 9 years
- Key stored in CA HSM, never on card

**1e. FASC-N encoding** (`pkg/piv/fascn.go`):
- 5-bit BCD encoding with parity
- Start/end sentinels, field separators
- `AllNines()` function returning the 25-byte PIV-I FASC-N
- `Encode(agencyCode, systemCode, credentialNumber, ...)` for general use

**1f. AIA and CDP extensions**:
- Ensure all PIV profiles include configurable AIA (caIssuers + OCSP) and CDP URLs
- Today the URLs are CA-wide: `CAConfig.CRLDistributionPoints` and `CAConfig.OCSPServers` (`pkg/ca/types.go:69`, `:73`); there are no per-profile options

### Phase 2: OCSP Responder — Done (different layout)

Built as `pkg/ca/ocsp.go`, not a `pkg/ca/ocsp/` package: `NewOCSPResponder` and `OCSPResponder.HandleRequest` (`pkg/ca/ocsp.go:141`) parse an RFC 6960 request and return a signed response, with a response cache (`getCachedResponse`, `cacheResponse`).

**Still open**: an 18-hour CRL publication schedule (FPKI requirement) tied to PIV-I issuance.

### Phase 3: PIV Data Object Construction — Open

Implement `pkg/piv/` — data object builders for CHUID, CCC, Discovery Object, and Security Object.

**Files**:
- `pkg/piv/chuid.go` — CHUID builder with FASC-N, UUID, expiration, CMS signature
- `pkg/piv/ccc.go` — Card Capability Container builder
- `pkg/piv/discovery.go` — Discovery Object with PIN policy
- `pkg/piv/security_object.go` — CMS SignedData over data object hashes
- `pkg/piv/fascn.go` — FASC-N BCD encoding
- `pkg/piv/tlv.go` — BER-TLV encoding/decoding
- `pkg/piv/data_objects.go` — Container tag constants and data group mappings

**CHUID construction requires**:
- FASC-N (all 9s for PIV-I)
- UUID (shared across all certs)
- Expiration date
- CMS signature using content signing key from HSM

**Security Object construction requires**:
- SHA-256 hashes of all data objects present on card
- LDS Security Object (ICAO format) containing hash map
- CMS SignedData wrapper signed with content signing key
- Content signing certificate included in CMS

### Phase 4: Key Escrow for Slot 9D — Open

Implement key archival and recovery for Key Management certificates (the only PIV slot where this is permitted). A general escrow layer exists (`pkg/escrow/`, KMIP and xkms federation backends) but nothing escrows PIV slot 9D keys.

**Requirements**:
- Encrypt and archive 9D private key material
- Recovery requires dual-person control or equivalent policy
- Archived key protected at same FIPS 140 level as live key
- Integration with existing `pkg/backend/` key storage

### Phase 5: PIV APDU Engine (`pkg/piv/`) — Open (partial engine in `xkey/pkg/ccid/`)

Core ISO 7816-4 / SP 800-73-4 command processor. There is no `pkg/piv/`. `xkey/pkg/ccid/bridge.go` has a PKCS#11-backed engine that selects the PIV AID (`AIDPIV`, `bridge.go:65`) and handles SELECT, VERIFY, PSO, READ BINARY, GENERATE ASYMMETRIC and GET DATA (`bridge.go:162`). GENERAL AUTHENTICATE, PUT DATA and GET RESPONSE are not handled, and the data objects of Phase 3 are not served.

**Files**:
- `pkg/piv/apdu.go` — APDU command/response types
- `pkg/piv/applet.go` — PIV applet state machine (not selected -> selected -> authenticated)
- `pkg/piv/commands.go` — Command dispatch (map-based, O(1) lookup)
- `pkg/piv/auth.go` — VERIFY (PIN), GENERAL AUTHENTICATE (challenge-response)
- `pkg/piv/config.go` — PIV-I configuration (UUID, org, algorithms)
- `pkg/piv/errors.go` — ISO 7816 status words

**APDU Commands**:

| INS | Name | Description |
|-----|------|-------------|
| `A4` | SELECT | Select PIV AID `A0 00 00 03 08 00 00 10 00 01 00` |
| `CB` | GET DATA | Retrieve data objects (CHUID, certs, Discovery) |
| `87` | GENERAL AUTHENTICATE | Challenge-response with slot key |
| `20` | VERIFY | PIN verification |
| `DB` | PUT DATA | Store data objects |
| `47` | GENERATE ASYMMETRIC KEY PAIR | Generate key in slot |
| `FD` | GET RESPONSE | Continue multi-part response |

**Key Backend Interface**:

```go
// PIVKeyBackend abstracts platform-specific key operations.
type PIVKeyBackend interface {
    Sign(slot Slot, algorithm Algorithm, data []byte) ([]byte, error)
    GetCertificate(slot Slot) (*x509.Certificate, error)
    StoreCertificate(slot Slot, cert *x509.Certificate) error
    GenerateKey(slot Slot, algorithm Algorithm) (crypto.PublicKey, error)
    SupportsAlgorithm(algorithm Algorithm) bool
}
```

### Phase 6: Virtual CCID Device (`xkey/pkg/ccid/`) — Done (different layout)

xkey presents a USB smart card reader to the host OS. The CCID message layer is `xkey/pkg/ccid/ccid.go` (`PC_to_RDR_XfrBlock` → `handleXfrBlock` → `RDR_to_PC_DataBlock`, `ccid.go:317`, `:391`); descriptors are in `descriptor.go`; APDUs go to the `PKCS11Bridge` of Phase 5. The USB transports (UHID or USB gadget) live in `pkg/fido2/uhid/` and `xkey/pkg/gadget/`; see [usb/ccid.md](../usb/ccid.md). There are no `uhid.go` or `transport.go` files in `xkey/pkg/ccid/`.

### Phase 7: Derived Credentials + Phone Provisioning — Open

Depends on Phase 1 (no PIV-I Card Auth profile exists yet). The desktop side of the pairing protocol already carries PIV methods (generate key, import cert, list slots, sign, get cert; `pkg/pairingproto/protocol_piv.go`), but none issues a PIV-I certificate. The xkey-android app lives in a separate repository and is not verified here; the plan assumes it has Noise_XX pairing with device attestation. This phase adds PIV credential provisioning over the existing secure channel.

**Flow**:
1. Phone is already paired via BLE Noise_XX (existing)
2. Phone generates PIV key in StrongBox for slot 9E (Card Authentication)
3. Phone sends CSR over Noise channel to desktop
4. Desktop CA signs the CSR using PIV-I Card Auth profile, returns certificate
5. Phone stores certificate alongside key, builds CHUID with shared UUID
6. Phone PIV applet is now provisioned and ready for NFC

**SP 800-157 Derived Credentials**: The phone key is a "derived credential" — generated on the phone, signed by the same CA. The Noise channel provides mutual authentication and confidentiality.

### Phase 8: Android HCE (`xkey-android`) — Open (separate repository, not verified here)

Implement `HostApduService` to present the phone as a contactless PIV card to NFC building access readers.

**Files**:
- `app/src/main/kotlin/.../nfc/PivHceService.kt` — `HostApduService` subclass
- `app/src/main/kotlin/.../nfc/PivApduProcessor.kt` — Bridge to PIV APDU engine
- `app/src/main/res/xml/hce_piv.xml` — AID registration for PIV AID

**Card Authentication (9E)** is used for contactless access because it does not require PIN entry — the phone's biometric/PIN unlock serves as cardholder verification per SP 800-73-4 Section 4.1.3.

## Testing Infrastructure

### Unit Tests (No Hardware)

Planned, not yet present: `pkg/piv/` and PIV profile tests do not exist. The planned engine, data objects, FASC-N encoding, and certificate profiles are pure Go and testable with standard Go unit tests.

```bash
# planned
go test ./pkg/piv/... -v -count=1
go test ./pkg/ca/ -run TestPIV -v -count=1
```

### Certificate Profile Validation

Use GSA's [fpkilint](https://github.com/GSA/fpkilint) and [CPCT](https://playbooks.idmanagement.gov/fpki/tools/cpct/) (Certificate Profile Conformance Tool) to validate generated certificates against FPKI profiles.

### Virtual Smart Card Testing with vpcd

[vpcd](https://frankmorgner.github.io/vsmartcard/) provides a TCP socket bridge for pcscd, enabling integration testing without physical hardware.

**Protocol**: TCP socket on port 35963, 2-byte big-endian length prefix framing.

Planned, not yet present: the compose file, `Dockerfile.piv-test` and the `piv-card` service below do not exist.

```yaml
# test/docker/docker-compose.piv.yml (planned)
services:
  vpcd:
    image: debian:bookworm-slim
    command: >
      bash -c "
        apt-get update && apt-get install -y pcscd pcsc-tools vsmartcard-vpcd &&
        mkdir -p /etc/reader.conf.d &&
        cat > /etc/reader.conf.d/vpcd <<EOF
        FRIENDLYNAME \"Virtual PCD\"
        DEVICENAME   /dev/null:35963
        LIBPATH      /usr/lib/pcsc/drivers/serial/libifdvpcd.so
        CHANNELID    0x35963
      EOF
        pcscd -f -d
      "
    ports:
      - "35963:35963"
    volumes:
      - pcscd-run:/var/run/pcscd

  piv-card:
    build:
      context: ../..
      dockerfile: test/docker/Dockerfile.piv-test
    depends_on:
      vpcd:
        condition: service_healthy
    environment:
      - VPCD_HOST=vpcd
      - VPCD_PORT=35963

  opensc-validator:
    image: debian:bookworm-slim
    command: >
      bash -c "
        apt-get update && apt-get install -y opensc pcsc-tools &&
        sleep 5 &&
        pkcs15-tool --list-certificates &&
        pkcs11-tool --list-objects --type cert &&
        opensc-tool --send-apdu 00A4040007A000000308000010000100 &&
        echo 'PIV validation passed'
      "
    depends_on:
      piv-card:
        condition: service_started
    volumes:
      - pcscd-run:/var/run/pcscd

volumes:
  pcscd-run:
```

APDUs are transport-agnostic — if the APDU engine passes validation via vpcd, it works via virtual CCID and Android HCE.

### Makefile Targets

Planned, not yet present. Today's PIV integration target is `make integration-test-piv` in `xkey/Makefile` (`./test/integration/piv/...`, line 580); the targets below, aimed at the planned `pkg/piv/` and vpcd harness, do not exist.

```makefile
test-piv:
	go test ./pkg/piv/... -v -count=1

test-piv-profiles:
	go test ./pkg/ca/ -run TestPIV -v -count=1

integration-test-piv:
	docker compose -f test/docker/docker-compose.piv.yml up --build --abort-on-container-exit

coverage-piv:
	go test ./pkg/piv/... -coverprofile=coverage-piv.out -covermode=atomic
	go tool cover -func=coverage-piv.out

bench-piv:
	go test ./pkg/piv/... -bench=. -benchmem -count=3
```

## Dependencies

| Phase | Depends On |
|-------|-----------|
| Phase 1 (Profile Compliance) | None — extends `pkg/ca/profiles.go` |
| Phase 2 (OCSP Responder) | Done (`pkg/ca/ocsp.go`) |
| Phase 3 (Data Objects) | Phase 1 (needs FASC-N, UUID, content signing cert) |
| Phase 4 (Key Escrow) | None — builds on `pkg/escrow/` and `pkg/backend/` |
| Phase 5 (APDU Engine) | Phase 3 (needs data objects to serve) |
| Phase 6 (Virtual CCID) | Done (`xkey/pkg/ccid/`) |
| Phase 7 (Phone Provisioning) | Phase 1 + existing Noise pairing |
| Phase 8 (Android HCE) | Phase 5 + Phase 7 |
| vpcd Testing | Phase 5 |

## Scope: PIV-I (Not Federal PIV)

xkey targets **PIV-Interoperable** (PIV-I), not full federal PIV:

| Feature | Federal PIV | PIV-I (xkey) |
|---------|------------|--------------|
| Enrollment | Federal agency | Self/enterprise |
| FASC-N | Agency-assigned | All 9s (non-federal indicator) |
| UUID in CHUID | Optional | Required (primary identifier) |
| Card Authentication (9E) | Required | Required |
| PIV Auth (9A) | Required + PIN | Required + PIN |
| Digital Signature (9C) | Required | Required |
| Key Management (9D) | Required | Required + key escrow |
| Biometrics on card | Required | Not supported |
| CHUID | Required | Required (UUID-based) |
| CCC | Required | Required (minimal) |
| Security Object | Required | Required (CMS signed) |
| Discovery Object | Required | Required |
| FIPS 140 Level 2 | Required (card crypto module) | Covered by HSM/TPM backends |
| Background investigation | Required | Not required |
| Cross-certification | Required (Federal PKI) | Deploying org via CertiPath/IdenTrust |
| Certificate profiles | FPKI Common Policy | PIV-I policy OIDs |

## References

- [FIPS 201-3](https://csrc.nist.gov/publications/detail/fips/201/3/final) — PIV of Federal Employees
- [NIST SP 800-73-4](https://csrc.nist.gov/publications/detail/sp/800-73/4/final) — Interfaces for PIV
- [NIST SP 800-78-5](https://csrc.nist.gov/publications/detail/sp/800-78/5/final) — Cryptographic Algorithms for PIV
- [NIST SP 800-76-2](https://csrc.nist.gov/publications/detail/sp/800-76/2/final) — Biometric Specifications for PIV
- [NIST SP 800-157](https://csrc.nist.gov/publications/detail/sp/800-157/final) — Derived PIV Credentials
- [NIST SP 800-63-4](https://csrc.nist.gov/publications/detail/sp/800-63/4/final) — Digital Identity Guidelines
- [OMB M-22-09](https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf) — Federal Zero Trust Strategy
- [FPKI PIV-I Certificate Profiles](https://www.idmanagement.gov/docs/fpki-x509-cert-profiles-pivi.pdf)
- [Common Policy Certificate Profile](https://www.idmanagement.gov/docs/fpki-x509-cert-profile-common.pdf)
- [GSA fpkilint](https://github.com/GSA/fpkilint) — Certificate Profile Conformance Tool
- [CertiPath Cross-Certification](https://certipath.com/services/federated-trust/become-a-member-2/roadmap-to-cross-certification-2/)
- [PIV-I 101](https://www.idmanagement.gov/university/pivi/) — IDManagement.gov
- [ISO 7816-4](https://www.iso.org/standard/54550.html) — Smart Card Commands
- [USB CCID](https://www.usb.org/document-library/class-specification-usb-chip-smart-card-interface-devices-11) — Smart Card Interface Device Class
- [vsmartcard vpcd](https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html) — Virtual Smart Card
- [Android HCE](https://developer.android.com/develop/connectivity/nfc/hce) — Host Card Emulation
- [Phishing-Resistant Authenticator Playbook](https://www.idmanagement.gov/playbooks/altauthn/) — IDManagement.gov
