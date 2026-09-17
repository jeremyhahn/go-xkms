# CA Architecture

## Overview

The Certificate Authority module implements a hierarchical PKI architecture with hardware security integration through go-xkms and distributed storage through go-objstore.

## CA Module

go-xkms owns the CA as a first-class module. The CA (`go-xkms/pkg/ca`) and
ACME (`go-xkms/pkg/acme`) ship directly within go-xkms, providing:

```
┌─────────────────────────────────────────────────────────────┐
│                         go-xkms                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  CA & ACME  (pkg/ca, pkg/acme)                         ││
│  │  • CSR Signing & Certificate Issuance                   ││
│  │  • Key Generation (RSA, ECDSA, Ed25519)                 ││
│  │  • Revocation & CRL Generation                          ││
│  │  • Trust Chain Management                               ││
│  │  • Per-Key Keystore Routing                             ││
│  │  • ACME Protocol (RFC 8555)                             ││
│  │  • TCG Enrollment (enroll-01, device-attest)            ││
│  │  • IDevID/IAK Certificate Issuance                      ││
│  │  • Policy Engine, Certificate Linting                   ││
│  └─────────────────────────────────────────────────────────┘│
│                            │                                 │
│                     uses   │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  go-xkms Backends                                      ││
│  │  • KeyStore (TPM, PKCS#11, KMS, Software)               ││
│  │  • CertStore (File, S3, Database)                       ││
│  │  • crypto.Signer Interface                              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Module Features

- **Single Source of Truth**: CA and ACME code lives in go-xkms, eliminating duplication
- **Consistent Behavior**: All consumers of go-xkms CA behave identically
- **Simplified Maintenance**: Bug fixes benefit all consumers automatically
- **Per-Key Keystore Routing**: Each key in a CA identity can be stored in a different backend (software, TPM2, PKCS#11)

## CA Hierarchy

```
                    +------------------------+
                    |       Root CA          |
                    |  (Self-Signed, Index 0)|
                    +------------------------+
                    | Subject: Root CA       |
                    | MaxPathLen: 2          |
                    | KeyUsage: CertSign,    |
                    |   CRLSign, DigitalSig  |
                    | IsCA: true             |
                    +------------------------+
                              |
                    Signs     |
                              v
                    +------------------------+
                    |   Intermediate CA      |
                    |  (Issuing CA, Index 1) |
                    +------------------------+
                    | Subject: Intermediate  |
                    | MaxPathLen: 1          |
                    | KeyUsage: CertSign,    |
                    |   CRLSign, DigitalSig  |
                    | IsCA: true             |
                    +------------------------+
                              |
                    Signs     |
          +---------+---------+---------+
          |         |         |         |
          v         v         v         v
       +------+  +------+  +------+  +------+
       | End  |  | End  |  | TPM  |  | TPM  |
       |Entity|  |Entity|  |IDevID|  | IAK  |
       +------+  +------+  +------+  +------+
```

## Key Storage Architecture

The CA uses go-xkms's multi-backend architecture for secure key management:

```
+-----------------------------------------------------------------------+
|                           CA Instance                                  |
+-----------------------------------------------------------------------+
|                                                                       |
|   +-------------------+    +-------------------+    +---------------+ |
|   | Root KeyStore     |    | Intermediate      |    | Object Store  | |
|   | (Per-CA Instance) |    | KeyStore          |    | (Per-CA)      | |
|   +-------------------+    +-------------------+    +---------------+ |
|           |                        |                       |          |
|           v                        v                       v          |
|   +-------------------+    +-------------------+    +---------------+ |
|   | Root CertStore    |    | Intermediate      |    | Revocation    | |
|   | (Per-CA Instance) |    | CertStore         |    | Data          | |
|   +-------------------+    +-------------------+    +---------------+ |
|                                                                       |
+-----------------------------------------------------------------------+
                    |                    |
                    v                    v
+-----------------------------------------------------------------------+
|                     go-xkms Backends                               |
+-----------------------------------------------------------------------+
|                                                                       |
|   +----------------+    +----------------+    +--------------------+  |
|   |   Software     |    |    TPM 2.0     |    |    PKCS#11/HSM    |  |
|   |   (PKCS#8)     |    |    Backend     |    |     Backend       |  |
|   +----------------+    +----------------+    +--------------------+  |
|   | File-based     |    | Hardware-bound |    | Hardware Security |  |
|   | Encrypted keys |    | Non-exportable |    | FIPS 140-2/3      |  |
|   | Dev/Test       |    | PCR policies   |    | Production        |  |
|   +----------------+    +----------------+    +--------------------+  |
|                                                                       |
+-----------------------------------------------------------------------+
```

## Per-CA Store Architecture

Each CA (Root and Intermediate) maintains its own isolated stores:

```go
type CA struct {
    // Root CA stores
    rootKeyStore            xkms.Backend
    rootCertStore           certstore.CertStore
    rootObjectStore         common.Storage

    // Intermediate CA stores
    intermediateKeyStore    xkms.Backend
    intermediateCertStore   certstore.CertStore
    intermediateObjectStore common.Storage

    // Factory interfaces for store creation
    keyStoreFactory         KeyStoreFactory
    certStoreFactory        CertStoreFactory
    objectStoreFactory      ObjectStoreFactory
}
```

This separation ensures:
- **Key Isolation**: Root and Intermediate CA keys are stored separately
- **Access Control**: Different security policies per CA tier
- **Audit Trail**: Clear separation of CA operations
- **Backup/Recovery**: Independent backup strategies per CA

## Canonical Certificate Issuance

`pkg/ca` is the single implementer of CA-issued certificate creation. Every
certificate this project signs — root, intermediate, end entity, TCG
endorsement / attestation / device identity, ACME subscriber and per-tenant CA
— is built and signed by `ca.Issuer`.

```
       caller                      pkg/ca                        crypto/x509
         |                            |                               |
         |  CertificateSpec           |                               |
         |  (subject, validity, SANs, |                               |
         |   profile, extensions)     |                               |
         |--------------------------->|                               |
         |                            |                               |
         |                     Issuer.Template                        |
         |                       1. subject / validity / names        |
         |                       2. issuer name + authority key id    |
         |                       3. Profile.Apply                     |
         |                          (key usage, EKU, basic            |
         |                           constraints, policies)           |
         |                       4. Identity endpoints                |
         |                          (CRL / OCSP / AIA)                |
         |                       5. caller extensions                 |
         |                            |                               |
         |                     Issuer.Sign  ---- CreateCertificate --->|
         |                            |                               |
         |  *x509.Certificate         |                               |
         |<---------------------------|                               |
```

### The two halves of the seam

A caller states **what** it wants; `pkg/ca` decides **how** that becomes an
X.509 certificate.

| Owned by the caller (`CertificateSpec`) | Owned by `pkg/ca` |
| --- | --- |
| Serial, subject, validity window | Key usage, extended key usage |
| Subject alternative names | Basic constraints and path length |
| Public key, signature algorithm | Certificate policies |
| Path-specific extra extensions | CRL / OCSP / AIA endpoints |
| Which **profile** classifies the certificate | Issuer name, authority key identifier |

`CertificateSpec` deliberately has no key-usage, extended-key-usage or
basic-constraints field. Those are policy, and policy belongs to the profile.
`Issuer.Issue` requires a profile: that requirement is what guarantees no
issuance path can bypass `Profile.Apply`.

### The issuer is explicit

`ca.Issuer` carries the signing key, the issuing certificate and the issuing
identity as values rather than resolving them from a process-wide CA:

```go
type Issuer struct {
    Signer      crypto.Signer      // signs the certificate
    Certificate *x509.Certificate  // nil => self-signed (root creation)
    Identity    *Identity          // supplies CRL / OCSP / AIA endpoints
}
```

This is what makes multi-tenant issuance possible. The ACME admin service
creates a per-tenant root by passing an `Issuer` with a nil `Certificate` and
the tenant's own key; it creates a tenant intermediate by passing the tenant
root, or the platform CA, as the parent. The cluster provisioner does the same
through `SignOptions.Signer` / `SignOptions.IssuerCert`.

### Profiles

Profiles are the policy vocabulary. A change to a profile reaches every path
that issues with it — that is the point of routing everything through one
issuer.

| Profile | Used by | Key usage | Basic constraints |
| --- | --- | --- | --- |
| `ca` | root, intermediate, tenant root, tenant intermediate | certSign, cRLSign, digitalSignature | CA, path length from request |
| `server`, `client`, `code-signing`, `email`, `ocsp-responder`, `timestamping` | `SignCSR` with a named profile | per purpose | end entity |
| `acme-leaf` | ACME issuance pipeline | digitalSignature, keyEncipherment | omitted |
| `tcg-ek` | `IssueEKCertificate` | keyEncipherment | omitted |
| `tcg-ak`, `tcg-iak` | `IssueAKCertificate`, `SignTCGCSRIDevID` | digitalSignature | omitted |
| `tcg-idevid` | `SignTCGCSRIDevID` | digitalSignature, keyEncipherment | omitted |
| `fido2-attestation` | `SignCSR` for a FIDO2 authenticator attestation key | digitalSignature | CA:false |

A CSR-signing caller that names no profile is issued with an anonymous TLS leaf
profile carrying whatever key usage and extended key usage its `SignOptions`
asked for, so even that case goes through `Profile.Apply`.

#### FIDO2 attestation

`fido2-attestation` issues the certificate a FIDO2 authenticator presents with
a `packed` attestation statement. WebAuthn Level 2 §8.2.1 states what such a
certificate must carry, and a relying party checks all of it on every
registration, so the profile enforces the same requirements at issuance:

| §8.2.1 requirement | Where the value comes from |
| --- | --- |
| Subject-C (PrintableString) | the issuing CA's own subject |
| Subject-O (UTF8String) | the issuing CA's own subject |
| Subject-OU == `Authenticator Attestation` | the profile, literally |
| Subject-CN (UTF8String) | the request |
| `id-fido-gen-ce-aaguid`, non-critical, 16-byte OCTET STRING | the request, if the profile permits that AAGUID |
| Basic Constraints CA:false | the profile |

The country and organisation are the CA's because §8.2.1 wants the attestation
*vendor's*, and a device cannot assert either credibly; the operator running the
CA is the vendor of record for the authenticators it provisions.

The profile refuses rather than issues something short. A request with no
AAGUID extension, a malformed one, an AAGUID the profile does not certify, or an
issuing CA whose subject has no country or organisation is rejected — an
attestation certificate missing any §8.2.1 field is rejected by the relying
party that receives it, so issuing one would only move the failure to first
registration, where nothing reports why attestation stopped working.

Extensions are otherwise **not** copied from a certificate signing request. The
request's extensions reach a profile through `CertificateRequest.CSRExtensions`
so that a profile can opt into the ones it understands; `fido2-attestation` is
the only profile that does, and only for `id-fido-gen-ce-aaguid`. A requester
that could name its own basic constraints or key usage would be issuing to
itself.

**Authenticator model allowlist.** The AAGUID is not copied verbatim. The
profile carries the set of AAGUIDs it may certify, and a request naming any
other is refused with `ErrFIDO2AttestationAAGUIDNotPermitted`, which names the
refused AAGUID in RFC 4122 form. The provisioning ceremony — the requester held
the device and its Security Officer PIN — proves possession, and possession says
nothing about what the device is, so it is not a basis for the CA to vouch for a
model.

`NewFIDO2AttestationProfile()` called with no arguments permits exactly
`ca.XKeyAAGUID`, the one authenticator this project ships, and that is what
`NewDefaultProfileRegistry` installs. No argument permits every AAGUID: a
control that switched itself off when left unconfigured would read as
enforcement while providing none. An operator provisioning other models lists
every AAGUID the CA may certify and registers the result:

```go
myCA.Profiles().Register(ca.ProfileNameFIDO2Attestation,
    ca.NewFIDO2AttestationProfile(ca.XKeyAAGUID, vendorAAGUID))
```

The listed AAGUIDs are the whole policy — `ca.XKeyAAGUID` is not unioned in, so
list it too if xkey devices are among the models. Registering is a deliberate
administrative act, distinct from provisioning, and it is how the first device
of a newly approved model is admitted.

The remaining assumption is stated plainly: a permitted AAGUID is certified on
the operator's say-so, and the CA does not otherwise verify that the device
before it is the model the AAGUID names.

Registering a profile against a CA replaces it everywhere:

```go
stricter := ca.NewProfileBuilder(ca.ProfileNameCA).
    WithKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).
    AsCA().
    Build()
myCA.Profiles().Register(ca.ProfileNameCA, stricter)
```

After that, the platform root, every intermediate and every per-tenant CA the
deployment creates carry the stricter key usage.

### Signing the same template twice

Two callers must sign one template more than once and therefore use
`Issuer.Sign` directly rather than `Issuer.Issue`:

- the **Certificate Transparency pipeline** (`pkg/acme/issuance`), which signs
  a precertificate carrying a poison extension and then a final certificate
  carrying the SCT list;
- the **hybrid ML-DSA signer** (`pkg/ca/hybrid.go`), which signs once to obtain
  a TBS to countersign with the quantum key, and again to embed the
  countersignature.

Both build their template through `Issuer.Template`, so they inherit the same
profile and endpoint policy as everything else. `Issuer.Sign` is the only place
`x509.CreateCertificate` is called for a CA-issued certificate.

### Regression coverage

`testutil.PolicyFingerprint` reduces a certificate to its policy surface —
extensions with their raw values, key usage, extended key usage, basic
constraints, path length, endpoints and validity duration — excluding the
serial, the absolute timestamps and everything derived from key material. The
`TestCertificatePolicy_*` suites pin that fingerprint for every former call
site, and assert that adding an OCSP responder to the issuing identity is
observable from all of them.

## Certificate Lifecycle

```
+-------------------+     +-------------------+     +-------------------+
|  Key Generation   | --> | Certificate       | --> |   Certificate     |
|                   |     | Signing Request   |     |   Issuance        |
+-------------------+     +-------------------+     +-------------------+
        |                         |                         |
        v                         v                         v
+-------------------+     +-------------------+     +-------------------+
| Store in KeyStore |     | Verify CSR        |     | Store in          |
| (go-xkms)     |     | Signature         |     | CertStore         |
+-------------------+     +-------------------+     +-------------------+
                                  |
                                  v
                          +-------------------+
                          | Build Certificate |
                          | Template          |
                          +-------------------+
                                  |
                                  v
                          +-------------------+
                          | Sign with CA Key  |
                          | (crypto.Signer)   |
                          +-------------------+
```

### Certificate Request Flow

```
Client                       CA                        KeyStore
  |                          |                            |
  |  CSR (PEM)               |                            |
  |------------------------->|                            |
  |                          |                            |
  |                          |  Get CA Signer             |
  |                          |--------------------------->|
  |                          |                            |
  |                          |  crypto.Signer             |
  |                          |<---------------------------|
  |                          |                            |
  |                          |  Create Certificate        |
  |                          |  Template                  |
  |                          |                            |
  |                          |  x509.CreateCertificate    |
  |                          |  (template, parent,        |
  |                          |   pubKey, signer)          |
  |                          |                            |
  |  Signed Certificate      |                            |
  |<-------------------------|                            |
```

## Trust Chain Management

### Chain Building

```
+------------------+
| End-Entity Cert  |  <- Leaf certificate
+------------------+
        |
        | Issuer: Intermediate CA
        v
+------------------+
| Intermediate CA  |  <- Signing CA
+------------------+
        |
        | Issuer: Root CA
        v
+------------------+
|    Root CA       |  <- Trust anchor
+------------------+
        |
        | Self-signed
        v
+------------------+
|   Trust Store    |
+------------------+
```

### Cross-Signing Support

```
                    Original Root CA
                          |
                          | Signs
                          v
              +----------------------+
              |   Intermediate CA    |
              |   (Original Chain)   |
              +----------------------+
                          |
        Cross-Sign        |         Original Sign
              |           |               |
              v           v               v
      +-------------+  +-------------+  +-------------+
      | External CA |  |End-Entity 1 |  |End-Entity 2 |
      | Trust Anchor|  +-------------+  +-------------+
      +-------------+
              |
              v
      +----------------------+
      |  Cross-Signed Cert   |
      |  (Same Key, New Sig) |
      +----------------------+
```

Cross-signed certificates enable:
- **Trust Migration**: Transition from old root to new root
- **Multiple Trust Anchors**: Support clients trusting different CAs
- **Interoperability**: Bridge different PKI hierarchies

## Multi-Key Support

The CA supports multiple key algorithms per CA identity:

```yaml
identity:
  - subject:
      cn: "Intermediate CA"
    keys:
      # Software RSA
      - algorithm: RSA
        rsa-key-size: 2048
        store-type: software

      # Software ECDSA
      - algorithm: ECDSA
        ecc-curve: P-256
        store-type: software

      # TPM2 RSA
      - algorithm: RSA
        rsa-key-size: 2048
        store-type: tpm2

      # TPM2 ECDSA
      - algorithm: ECDSA
        ecc-curve: P-256
        store-type: tpm2
```

Multi-key benefits:
- **Algorithm Agility**: Support clients with different algorithm requirements
- **Migration Path**: Gradual transition between algorithms
- **Hybrid Security**: Combine software and hardware-backed keys
- **Performance Optimization**: Use appropriate keys for different workloads

## Initialization Modes

### Auto-Initialization (Default)

```go
config := ca.DefaultConfig()
authority, err := ca.New(config, certStore, objectStore)
// CA is fully initialized with root and intermediate certificates
```

### Lazy Initialization

```go
config := ca.DefaultConfig()
config.LazyInitialization = true
authority, err := ca.NewWithParams(ca.Params{
    Config:      config,
    CertStore:   certStore,
    ObjectStore: objectStore,
})

// Later, explicitly initialize
err = authority.Init() // Creates new CA
// OR
err = authority.Load() // Loads existing CA
```

## Factory Pattern for Per-CA Stores

```go
// KeyStoreFactory creates separate keystores per CA identity
type KeyStoreFactory interface {
    CreateKeyStore(cn string) (interface{}, error)
}

// CertStoreFactory creates separate certstores per CA identity
type CertStoreFactory interface {
    CreateCertStore(cn string) (interface{}, error)
}

// ObjectStoreFactory creates separate objectstores per CA identity
type ObjectStoreFactory interface {
    CreateObjectStore(cn string) (interface{}, error)
}
```

Example implementation:

```go
type FileBasedKeyStoreFactory struct {
    baseDir string
}

func (f *FileBasedKeyStoreFactory) CreateKeyStore(cn string) (interface{}, error) {
    caDir := filepath.Join(f.baseDir, cn)
    storage, _ := file.New(caDir)
    backend, _ := pkcs8.NewBackend(&pkcs8.Config{KeyStorage: storage})
    return xkms.New(&xkms.BackendConfig{Backend: backend})
}
```

## Object Storage Layout

```
objectstore/
+-- revocations/
|   +-- {cn}/
|       +-- {serial}.json       # Revocation info
+-- crls/
|   +-- distribution/
|       +-- {hash}.crl          # Downloaded CRLs
+-- cross-signed/
|   +-- {issuer_cn}/
|       +-- {subject_cn}.pem    # Cross-signed certificates
+-- xsigned/
|   +-- {cn}/
|       +-- {issuer_cn}.crt     # Alternative cross-sign storage
+-- attestation/
    +-- {cn}/
        +-- quotes/             # TPM quotes
        +-- eventlogs/          # Platform event logs
        +-- pcrs/               # PCR values
```

## Security Model

### Key Protection Layers

| Layer | Software | TPM 2.0 | PKCS#11/HSM |
|-------|----------|---------|-------------|
| Key Storage | Encrypted file | TPM NVRAM | HSM secure storage |
| Key Access | Password/API | PCR policy | PIN/token |
| Key Export | Supported | Not possible | Configurable |
| Operations | In-memory | TPM commands | HSM commands |

### Access Control

```
+------------------------+
|     Application        |
+------------------------+
          |
          v
+------------------------+
|    CA API Layer        |
| - Input validation     |
| - Authorization check  |
+------------------------+
          |
          v
+------------------------+
|   KeyStore Facade      |
| - Backend routing      |
| - Key attributes       |
+------------------------+
          |
          v
+------------------------+
|   Backend Layer        |
| - TPM policies         |
| - HSM access control   |
| - File permissions     |
+------------------------+
```

## Component Interactions

```
+------------------+     +-----------------+     +------------------+
|   ACME Server    |     |   Admin API     |     |   TPM Client     |
+------------------+     +-----------------+     +------------------+
         |                       |                       |
         v                       v                       v
+--------------------------------------------------------------------+
|           go-xkms Certificate Authority (pkg/ca, pkg/acme)         |
+--------------------------------------------------------------------+
|  +---------------+  +---------------+  +---------------+           |
|  | ACME Protocol |  | TCG Enroll    |  | Policy Engine |           |
|  +---------------+  +---------------+  +---------------+           |
|  +---------------+  +---------------+  +---------------+           |
|  | CSR Signing   |  | Revocation    |  | Chain Build   |           |
|  +---------------+  +---------------+  +---------------+           |
|  +---------------+  +---------------+  +---------------+           |
|  | Cert Issue    |  | CRL Generate  |  | Multi-Key     |           |
|  +---------------+  +---------------+  +---------------+           |
+--------------------------------------------------------------------+
         |                       |                       |
         v                       v                       v
+------------------+     +-----------------+     +------------------+
|    KeyStore      |     |   CertStore     |     |   ObjectStore    |
|  (go-xkms)      |     |   (go-xkms)     |     |  (go-objstore)   |
+------------------+     +-----------------+     +------------------+
```

## Per-Key Multi-Keystore Routing

The CA supports routing each key in an identity's `Keys` slice to a
different backend — software PKCS#8, TPM 2.0, or PKCS#11 — within the same
CA instance. This model is additive and fully backward-compatible.

### Old Model (single keystore)

Every key in a CA identity was handled by a single injected `xkms.Backend`
(`ca.keyStore`). All operations resolved to that one backend.

### New Model (per-key routing)

When `Params.BackendForStore` is set, each key is routed to the backend
whose `StoreType` matches `KeyConfig.StoreType`. The CA builds an internal
`keystoreMap map[types.StoreType]xkms.Backend` during construction:

```
identity.Keys:
  Keys[0]  StoreType=software  ──►  software Backend  (primary signing key)
  Keys[1]  StoreType=tpm2      ──►  TPM 2.0 Backend   (secondary)
  Keys[2]  StoreType=software  ──►  software Backend   (secondary)
  Keys[3]  StoreType=tpm2      ──►  TPM 2.0 Backend   (secondary)
```

### Primary vs. Secondary Keys

- **Keys[0]** is the **primary signing key**. Its public key is bound in
  the CA certificate and all certificate issuance signs with this key.
- **Keys[1..n]** are **secondary keys**, generated in their respective
  backends at `Init` time for backup, rotation, or future algorithm-agile
  signing (algorithm-agile signing is out of scope for the current release).
  Secondary keys are intentionally skipped during `Load` because the CA
  certificate binds only the primary public key.

### keystoreMap and resolveKeyBackend

The `BackendForStoreFunc` passed via `Params.BackendForStore` is called
**once per unique `StoreType`** found in the identity's `Keys` slice, not
once per key. The CA caches results so the factory is never invoked twice for
the same `(cn, storeType)` pair.

`resolveKeyBackend(storeType)` returns the cached backend for the given
`StoreType`, or falls back to `ca.keyStore` when no entry exists in the map.

### Backward-Compatible Fallback

When `Params.BackendForStore` is nil:

- `keystoreMap` is not populated.
- Every key resolves to `ca.keyStore` (the single injected backend).
- Behavior is identical to the legacy single-keystore path — zero behavior
  change for existing callers.

See [Multi-Keystore Routing](multi-keystore.md) for YAML configuration and
worked examples.

## See Also

- [Configuration Reference](configuration.md)
- [Multi-Keystore Routing](multi-keystore.md)
- [Certificate Types](certificate-types.md)
- [API Reference](api-reference.md)
