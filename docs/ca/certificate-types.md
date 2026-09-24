# Certificate Types

## Overview

The CA module supports various certificate types for different use cases, from standard X.509 PKI certificates to TPM-specific device identity certificates per TCG specifications.

## Certificate Hierarchy

```
+---------------------------+
|       Root CA             |
|  Self-signed, IsCA=true   |
|  MaxPathLen=2             |
+---------------------------+
            |
            v
+---------------------------+
|    Intermediate CA        |
|  Signed by Root           |
|  IsCA=true, MaxPathLen=1  |
+---------------------------+
            |
     +------+------+
     |      |      |
     v      v      v
+-------+ +-------+ +-------+
|End    | |  TPM  | |  TPM  |
|Entity | |IDevID | | IAK   |
+-------+ +-------+ +-------+
```

## Root CA Certificates

Root CA certificates are self-signed trust anchors that form the foundation of the PKI hierarchy.

### Characteristics

| Attribute | Value |
|-----------|-------|
| IsCA | true |
| MaxPathLen | 2 (allows 2 levels of intermediate CAs) |
| BasicConstraintsValid | true |
| KeyUsage | CertSign, CRLSign, DigitalSignature |
| Self-Signed | Issuer = Subject |
| Validity | Typically 15-25 years |

### Certificate Template

```go
template := &x509.Certificate{
    SerialNumber:          generateSerialNumber(),
    Subject:               ca.buildSubject(&identity.Subject),
    NotBefore:             time.Now().Add(-1 * time.Minute),
    NotAfter:              time.Now().AddDate(identity.Valid, 0, 0),
    KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign |
                           x509.KeyUsageDigitalSignature,
    IsCA:                  true,
    MaxPathLenZero:        false,
    MaxPathLen:            2,
    BasicConstraintsValid: true,
}
```

### Security Considerations

- Store root CA keys in hardware security modules (TPM/HSM)
- Keep root CA offline when not signing intermediate CAs
- Use strong algorithms (RSA-4096 or ECDSA P-384+)
- Implement strict access controls and audit logging

## Intermediate CA Certificates

Intermediate CAs (also called Issuing CAs) are signed by the Root CA and perform day-to-day certificate issuance.

### Characteristics

| Attribute | Value |
|-----------|-------|
| IsCA | true |
| MaxPathLen | 1 (allows 1 level of sub-CAs) or 0 (leaf-only) |
| BasicConstraintsValid | true |
| KeyUsage | CertSign, CRLSign, DigitalSignature |
| Issuer | Root CA Subject |
| Validity | Typically 5-10 years |

### Certificate Template

```go
template := &x509.Certificate{
    SerialNumber:          generateSerialNumber(),
    Subject:               ca.buildSubject(&identity.Subject),
    NotBefore:             time.Now().Add(-1 * time.Minute),
    NotAfter:              time.Now().AddDate(identity.Valid, 0, 0),
    KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign |
                           x509.KeyUsageDigitalSignature,
    IsCA:                  true,
    MaxPathLenZero:        false,
    MaxPathLen:            1,
    BasicConstraintsValid: true,
    Issuer:                rootCert.Subject,
    AuthorityKeyId:        rootCert.SubjectKeyId,
}
```

### Benefits of Intermediate CAs

- **Risk Mitigation**: Compromise of intermediate CA doesn't require root CA re-issuance
- **Operational Flexibility**: Can be online for automated issuance
- **Policy Separation**: Different intermediates for different purposes (TLS, code signing, etc.)

## End-Entity Certificates

End-entity certificates are issued to servers, clients, and users for authentication and encryption.

### TLS Server Certificates

| Attribute | Value |
|-----------|-------|
| IsCA | false |
| KeyUsage | DigitalSignature, KeyEncipherment |
| ExtKeyUsage | ServerAuth, ClientAuth |
| Validity | 398 days (CA/B Forum) |
| SANs | DNS names, IP addresses |

### TLS Client Certificates

| Attribute | Value |
|-----------|-------|
| IsCA | false |
| KeyUsage | DigitalSignature |
| ExtKeyUsage | ClientAuth |
| Subject | User or service identity |

### Certificate Request

```go
request := &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName:   "example.com",
        Organization: "Example Inc",
    },
    Valid: 398,
    SANS: &ca.SubjectAlternativeNames{
        DNS: []string{"example.com", "www.example.com"},
        IPs: []string{"192.168.1.1"},
    },
    KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
    ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
}
```

## TPM Device Identity Certificates

The CA supports TCG-compliant TPM device identity certificates per the TPM 2.0 Keys for Device Identity and Attestation specification.

### Endorsement Key (EK) Certificates

EK certificates certify the TPM's Endorsement Key, which is a non-migratable key used to establish TPM identity.

| Attribute | Value |
|-----------|-------|
| IsCA | false |
| KeyUsage | KeyEncipherment |
| ExtKeyUsage | ClientAuth, ServerAuth, tcg-kp-EKCertificate (2.23.133.8.1) |
| NotAfter | 99991231235959Z (Indefinite) |

tcg-kp-EKCertificate is an Extended Key Usage purpose (RFC 5280 section
4.2.1.12): the `tcg-ek` profile carries it in `UnknownExtKeyUsage`, so it is
encoded inside the certificate's standard ExtKeyUsage extension, not as a
standalone extension under the OID's own Id.

#### TCG Extensions

```go
extraExtensions := []pkix.Extension{
    // TPM Specification (TPM 2.0)
    CreateTPMSpecificationExtension(TPMSpecification{
        Family: "2.0", Level: 0, Revision: 0,
    }),

    // TPM Model and Serial
    CreateTPMModelExtension(request.ProdModel),
    CreateTPMVersionExtension(request.ProdSerial),

    // Trusted Platform extensions
    CreateTPKeyStoreExtension("TPM2"),
    CreateTPIssuerKeyStoreExtension(signingIdentity.GetStoreType()),
}
```

#### Issuing EK Certificates

```go
cert, err := authority.IssueEKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-ek",
    },
    ProdModel:    "TPM-Model-X",
    ProdSerial:   "SN12345",
    PermanentID:  "device-12345",
}, ekPublicKey)
```

### Initial Attestation Key (IAK) Certificates

IAK certificates certify the TPM's attestation key used for platform attestation and quote signing.

| Attribute | Value |
|-----------|-------|
| IsCA | false |
| KeyUsage | DigitalSignature |
| ExtKeyUsage | ClientAuth, ServerAuth, tcg-kp-AIKCertificate (2.23.133.8.3), tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3) |
| BasicConstraints | Asserted, CA:false |
| NotAfter | 99991231235959Z (Indefinite) |

tcg-kp-AIKCertificate is an Extended Key Usage purpose, carried in the
`tcg-ak`/`tcg-iak` profiles' `UnknownExtKeyUsage` rather than as a standalone
extension: WebAuthn L2 §8.3.1 requirement 4 ("TPM Attestation Statement
Certificate Requirements") and go-webauthn's `"tpm"` attestation format
verifier both look for the OID inside the standard ExtKeyUsage extension. The
explicit `BasicConstraints CA:false` satisfies requirement 5; the TCG TPM 2.0
Keys for Device Identity and Attestation specification never mentions Basic
Constraints for an AK/IAK certificate, so asserting it does not contradict
TCG.

**Pending decision (go-xkms#715):** WebAuthn L2 §8.3.1 requirement 2 requires
this certificate's Subject to be empty. TCG TPM 2.0 Keys for Device Identity
and Attestation v1.00 r12 §8 requires the opposite -- "the subject field MUST
contain a unique X.500 Distinguished Name" -- and this CA's certificate store
(`pkg/certstore.CertStore`) is keyed by `Subject.CommonName`, so an IAK/AK
certificate with an empty Subject cannot be stored or looked up
(`IAKCertificate(ctx, model, serial)`) the way it is today. The Subject and
SAN content described below are therefore unchanged pending an owner decision
among reconciling options (e.g. issuing a second, WebAuthn-profile-only
certificate over the same key). Everything else on this page reflects the
current, shipped behavior.

#### TCG Policy OIDs

```go
Policies: []x509.OID{
    TCGVerifiedTPMResidencyPolicy,  // 2.23.133.11.1.1
    TCGVerifiedTPMFixedPolicy,      // 2.23.133.11.1.2
}
```

#### Issuing AK Certificates

```go
cert, err := authority.IssueAKCertificate(&ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-ak",
    },
    SANS: &ca.SubjectAlternativeNames{
        DNS: []string{"device.example.com"},
    },
}, akPublicKey)
```

### Initial Device Identifier (IDevID) Certificates

IDevID certificates provide cryptographic device identity per IEEE 802.1AR.

| Attribute | Value |
|-----------|-------|
| IsCA | false |
| KeyUsage | DigitalSignature, KeyEncipherment |
| ExtKeyUsage | ClientAuth, ServerAuth |
| NotAfter | 99991231235959Z (Indefinite) |

#### TCG-CSR-IDEVID Signing

```go
iakDER, idevidDER, err := authority.SignTCGCSRIDevID(tcgCSR, &ca.CertificateRequest{
    Subject: ca.Subject{
        CommonName: "device-12345",
    },
})
```

The `SignTCGCSRIDevID` method:
1. Verifies the TCG-CSR-IDEVID signature using IAK or IDevID key
2. Validates TPM key attributes (restricted, fixedTPM, fixedParent)
3. Issues IAK certificate for attestation operations under the subject
   `IAKCommonName(model, serial)` = `iak-<model>-<serial>` (model and serial
   from the CSR), with the remaining subject fields copied from the request
4. Issues IDevID certificate for device identity under the request subject
5. Stores both certificates; because the two common names differ, the IDevID
   record does not replace the IAK record, and `IAKCertificate(ctx, model,
   serial)` returns the IAK later

TCG DevID §8 permits the IAK subject to differ from the IDevID subject. The
ACME enroll-01 handler names the IDevID `<model>-<serial>`, so on that path
the IAK is `iak-<model>-<serial>`.

## TCG Object Identifiers

### Certificate Type OIDs

| OID | Name | Description |
|-----|------|-------------|
| 2.23.133.8.1 | tcg-kp-EKCertificate | Endorsement Key Certificate |
| 2.23.133.8.2 | tcg-kp-PlatformCertificate | Platform Certificate |
| 2.23.133.8.3 | tcg-kp-AIKCertificate | Attestation Identity Key Certificate |

### Attribute OIDs

| OID | Name | Description |
|-----|------|-------------|
| 2.23.133.2.1 | tcg-at-tpmManufacturer | TPM Manufacturer |
| 2.23.133.2.2 | tcg-at-tpmModel | TPM Model |
| 2.23.133.2.3 | tcg-at-tpmVersion | TPM Version/Serial |
| 2.23.133.2.16 | tcg-at-tpmSpecification | TPM Specification Version |

### Policy OIDs

| OID | Name | Description |
|-----|------|-------------|
| 2.23.133.11.1.1 | tcg-verifiedTPMResidency | Key resides in TPM |
| 2.23.133.11.1.2 | tcg-verifiedTPMFixed | Key is non-migratable |

### Trusted Platform OIDs (Private Enterprise: 29377)

| OID | Name | Description |
|-----|------|-------------|
| 1.3.6.1.4.1.29377.101.1 | tp-issuerKeyStore | Issuer's keystore backend |
| 1.3.6.1.4.1.29377.101.2 | tp-keyStore | Subject's keystore backend |
| 1.3.6.1.4.1.29377.101.3 | tp-fips140 | FIPS 140 compliance indicator |

## Certificate Extensions

### Standard Extensions

| Extension | OID | Usage |
|-----------|-----|-------|
| Subject Key Identifier | 2.5.29.14 | Identifies the certificate's public key |
| Authority Key Identifier | 2.5.29.35 | Identifies the issuer's public key |
| Key Usage | 2.5.29.15 | Permitted cryptographic operations |
| Extended Key Usage | 2.5.29.37 | Application-specific key purposes |
| Basic Constraints | 2.5.29.19 | CA status and path length |
| Subject Alt Name | 2.5.29.17 | Alternative identities |
| CRL Distribution Points | 2.5.29.31 | CRL download locations |
| Authority Info Access | 1.3.6.1.5.5.7.1.1 | OCSP and issuer URLs |

### TPM-Specific Extensions

| Extension | Description |
|-----------|-------------|
| Permanent Identifier | Unique device identifier (RFC 4043) |
| Hardware Module Name | Hardware module identification (RFC 4108) |
| TPM Specification | TPM family, level, revision |
| Verified TPM Residency | Key proven to reside in TPM |
| Verified TPM Fixed | Key is non-migratable |

## Certificate Validity

### NotAfter Values

| Certificate Type | NotAfter |
|-----------------|----------|
| Root CA | NotBefore + 15-25 years |
| Intermediate CA | NotBefore + 5-10 years |
| TLS Server | NotBefore + 398 days |
| TPM EK/IAK/IDevID | 99991231235959Z (Indefinite) |

### Clock Skew Handling

All certificates have `NotBefore` backdated by 1 minute to handle clock synchronization issues between server and client:

```go
NotBefore: time.Now().Add(-1 * time.Minute)
```

## Serial Number Generation

Serial numbers are 128-bit cryptographically random values per RFC 5280:

```go
func generateSerialNumber() *big.Int {
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
    return serialNumber
}
```

## See Also

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [API Reference](api-reference.md)
