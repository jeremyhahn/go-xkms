# CA Architecture

## Overview

The Certificate Authority module implements a hierarchical PKI architecture with hardware security integration through go-xkms and distributed storage through go-objstore.

## go-xkms CA Embedding

go-trusted-ca embeds go-xkms's CA as the core certificate authority implementation. This layered architecture provides:

```
┌─────────────────────────────────────────────────────────────┐
│                      go-trusted-ca                           │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  TCG-Specific Features                                  ││
│  │  • ACME Protocol (RFC 8555)                             ││
│  │  • TCG Enrollment (enroll-01, device-attest)            ││
│  │  • IDevID/IAK Certificate Issuance                      ││
│  │  • Policy Engine, Certificate Linting                   ││
│  └─────────────────────────────────────────────────────────┘│
│                            │                                 │
│                     embeds │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  go-xkms CA (Embedded)                              ││
│  │  • CSR Signing & Certificate Issuance                   ││
│  │  • Key Generation (RSA, ECDSA, Ed25519)                 ││
│  │  • Revocation & CRL Generation                          ││
│  │  • Trust Chain Management                               ││
│  │  • Multi-Key Support                                    ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
                     uses   │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  go-xkms                                                 │
│  • KeyStore (TPM, PKCS#11, KMS, Software)                   │
│  • CertStore (File, S3, Database)                           │
│  • crypto.Signer Interface                                   │
└─────────────────────────────────────────────────────────────┘
```

### Benefits of CA Embedding

- **Single Source of Truth**: CA code lives in go-xkms, eliminating duplication
- **Consistent Behavior**: All projects using go-xkms CA behave identically
- **Simplified Maintenance**: Bug fixes benefit all consumers automatically
- **Clear Separation**: go-trusted-ca focuses on ACME/TCG, go-xkms CA handles core PKI

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
|              go-trusted-ca Certificate Authority                    |
+--------------------------------------------------------------------+
|  +---------------+  +---------------+  +---------------+           |
|  | ACME Protocol |  | TCG Enroll    |  | Policy Engine |           |
|  +---------------+  +---------------+  +---------------+           |
|                            |                                        |
|                    embeds  |                                        |
|                            v                                        |
|  +--------------------------------------------------------------+  |
|  |               go-xkms CA (Embedded)                      |  |
|  |  +---------------+  +---------------+  +---------------+      |  |
|  |  | CSR Signing   |  | Revocation    |  | Chain Build   |      |  |
|  |  +---------------+  +---------------+  +---------------+      |  |
|  |  +---------------+  +---------------+  +---------------+      |  |
|  |  | Cert Issue    |  | CRL Generate  |  | Multi-Key     |      |  |
|  |  +---------------+  +---------------+  +---------------+      |  |
|  +--------------------------------------------------------------+  |
+--------------------------------------------------------------------+
         |                       |                       |
         v                       v                       v
+------------------+     +-----------------+     +------------------+
|    KeyStore      |     |   CertStore     |     |   ObjectStore    |
|  (go-xkms)   |     |  (go-xkms)  |     |  (go-objstore)   |
+------------------+     +-----------------+     +------------------+
```

## See Also

- [Configuration Reference](configuration.md)
- [Certificate Types](certificate-types.md)
- [API Reference](api-reference.md)
