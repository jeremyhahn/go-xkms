# Architecture

go-xkms provides an ACME RFC-8555 compliant Certificate Authority with support for TCG (Trusted Computing Group) specifications, multi-tenancy, and hardware-backed key storage. (The ACME server was formerly the standalone `go-trusted-ca` project; it is now decommissioned and absorbed into go-xkms — CA in `pkg/ca`, ACME in `pkg/acme`.)

## Core Architecture

go-xkms uses a layered architecture with its CA (`pkg/ca`) as the foundation:

```
+---------------------------------------------------------------------------+
|                       go-xkms (pkg/acme)                                   |
+----------------------------------------------------------------------------+
|  ACME Server | TCG Enrollment | Admin API | Policy Engine                  |
+----------------------------------------------------------------------------+
|                   Certificate Authority (pkg/ca)                           |
|  +---------------------------------------------------------------------+  |
|  |                   go-xkms CA (pkg/ca core)                          |  |
|  |  CSR Signing | Cert Issuance | Revocation | CRL Generation          |  |
|  +---------------------------------------------------------------------+  |
+----------------------------------------------------------------------------+
|  go-xkms KeyStore   |   go-xkms CertStore   |  go-objstore  |             |
|  (TPM, PKCS#11, KMS)    |   (File, S3, Database)    |  (Storage)    |     |
+----------------------------------------------------------------------------+
```

This architecture ensures:
- **Unified CA Operations**: go-xkms CA provides consistent PKI operations across all consumers
- **Hardware Security**: go-xkms backends enable TPM 2.0, PKCS#11, and cloud KMS integration
- **TCG Compliance**: TCG-specific features (IDevID, IAK, attestation) are implemented on top of go-xkms CA
- **Multi-Protocol Support**: SDK provides gRPC, REST, QUIC, MCP, and Unix socket transports

## Unified SDK Dependency Chain

The ACME subsystem (`pkg/acme`) consumes the unified go-qrdb SDK to avoid duplicating functionality, and uses go-xkms's own CA and key-management packages directly. The diagram below shows which capabilities come from which layer:

```
+-------------------------------------------------------------------+
|                     go-xkms ACME (pkg/acme)                        |
|                                                                    |
|  Consumes from go-qrdb:                                           |
|    - Barrier (seal/unseal via ceremony service)                    |
|    - OpenSSL config parsing (pkg/system.LoadOpenSSLConfig)         |
|    - RBAC / IAM (policy engine, auth, JWT)                         |
|    - KV storage (PebbleDB, Raft consensus)                         |
|    - Ceremony service (initialization workflows)                   |
|                                                                    |
|  Consumes from go-xkms:                                           |
|    - Algorithms (GET /api/v1/algorithms, static until embedded)    |
|    - Key management (Software, TPM, PKCS#11, AWS/GCP/Azure KMS)   |
|    - Certificate storage (go-objstore backends)                    |
|    - FIDO2 operations (WebAuthn, attestation)                      |
|    - Hardware attestation (TPM 2.0)                                |
+-------------------------------------------------------------------+
         |                                    |
         v                                    v
+-------------------------------+    +-------------------------------+
|  go-qrdb                      |    |  go-xkms                      |
|                               |    |                               |
|  SDK (go-qrdb/sdk/go):       |    |  SDK (go-xkms/sdk/go):       |
|    - IAM / RBAC               |    |    - TPM access               |
|    - Auth (JWT)               |    |    - FIDO2 operations         |
|    - KV Storage               |    |    - Hardware attestation     |
|    - Raft Consensus           |    |    - Key management (KMS)     |
|    - Seal / Unseal            |    |    - Algorithm discovery      |
|    - Ceremony service         |    |                               |
|                               |    |  Server API:                  |
|  Packages (go-qrdb/pkg/):    |    |    GET /api/v1/algorithms     |
|    - system (OpenSSL config)  |    |    (dynamic per backend)      |
|    - database (DB lifecycle)  |    |                               |
|    - seal (Shamir SSS)        |    +-------------------------------+
|    - kvstore (KV interface)   |
|                               |
+-------------------------------+
```

### Capability Source Map

| Capability | Source Project | Import Path | Status |
|------------|---------------|-------------|--------|
| Barrier (seal/unseal) | go-qrdb | `go-qrdb/sdk/go` | Re-exported via ceremony service |
| OpenSSL defaults | go-qrdb | `go-qrdb/pkg/system` | `LoadOpenSSLConfig()` |
| Ceremony service | go-qrdb | `go-qrdb/sdk/go` | Fully exposed via SDK |
| RBAC / IAM | go-qrdb | `go-qrdb/sdk/go` | Stable SDK contract |
| KV storage | go-qrdb | `go-qrdb/sdk/go`, `go-qrdb/pkg/kvstore` | Direct + SDK |
| Algorithms | go-xkms | Local static list | Pending embedded transport |
| Key management | go-xkms | `go-xkms/sdk/go` | All backends supported |
| FIDO2 | go-xkms | `go-xkms/sdk/go` | WebAuthn integration |
| Certificate storage | go-xkms + go-objstore | `go-xkms/sdk/go` | All go-objstore backends |

### Barrier Re-export Chain

The barrier (seal/unseal) capability flows through go-qrdb's ceremony service:

```
go-xkms ACME (admin setup)
    |
    +-- calls go-qrdb ceremony service (via SDK)
            |
            +-- ceremony service manages barrier lifecycle
                    |
                    +-- go-qrdb/pkg/seal (Shamir's Secret Sharing)
                            |
                            +-- PebbleDB (encrypted storage)
```

The ceremony service encapsulates barrier initialization, key share distribution, and unseal operations. The ACME admin setup wizard delegates to this service rather than implementing barrier logic directly.

## SDK Dependency Model

The ACME subsystem now lives inside go-xkms (`pkg/acme`), so it uses go-xkms's own CA, key-management, and storage packages directly — no cross-repo SDK boundary applies there. The one remaining external boundary is go-xkms → go-qrdb, which goes through the go-qrdb SDK to keep that dependency stable:

```
+-----------------------------------------------------------------+
|                     go-xkms (pkg/acme, pkg/ca, ...)              |
|                                                                   |
|  External dependency — imports only:                              |
|    - github.com/jeremyhahn/go-qrdb/sdk/go      (RBAC, IAM,      |
|                                                    KV storage)    |
|    - github.com/jeremyhahn/go-qrdb/pkg/system   (OpenSSL config) |
|    - github.com/jeremyhahn/go-qrdb/pkg/*         (DB, KV, seal)  |
|                                                                   |
|  Internal: pkg/acme uses go-xkms/pkg/* (ca, tpm2, backend, ...)  |
|            directly — they are the same module.                   |
+-----------------------------------------------------------------+
         |
         v
+-------------------------------+
|  go-qrdb/sdk/go               |
|                               |
|  Provides:                    |
|    - IAM / RBAC               |
|    - Auth (JWT)               |
|    - KV Storage               |
|    - Raft Consensus           |
|    - Seal / Unseal            |
|                               |
|  Stable API contract          |
+-------------------------------+
```

### Dependency Rules

1. **go-xkms** depends on go-qrdb only through:
   - `go-qrdb/sdk/go` for the RBAC policy engine, auth, KV storage, Raft consensus, and seal operations
   - `go-qrdb/pkg/system` for OpenSSL configuration parsing
   - `go-qrdb/pkg/*` for database lifecycle, KV store interfaces, and seal primitives

2. **`pkg/acme` uses go-xkms packages directly** (`pkg/ca`, `pkg/tpm2`, `pkg/backend`, ...) — they are part of the same module; there is no internal SDK boundary inside go-xkms.

3. **The go-qrdb SDK provides a stable contract**:
   - go-qrdb internal refactoring does not break go-xkms
   - Semver-compatible API evolution

### Benefits

- **API Stability**: go-qrdb internal refactoring does not break go-xkms
- **Clean Boundaries**: a single, explicit go-xkms → go-qrdb SDK boundary
- **Type Safety**: SDK re-exports ensure type compatibility
- **Maintainability**: explicit contracts reduce coupling

## Deployment Modes

go-xkms's ACME server supports three deployment modes to match different operational requirements:

| Mode | Storage | Consensus | Use Case |
|------|---------|-----------|----------|
| **standalone** | PebbleDB | None | Development, testing, single-node |
| **raft** | PebbleDB | Single-node Raft | Production single-node with HA-ready |
| **cluster** | PebbleDB | Multi-node Raft | Production HA with automatic failover |

### Mode 1: Standalone (PebbleDB Direct)

Single-node deployment with direct PebbleDB storage. Simplest deployment with no consensus overhead.

```
+----------------------------------------------------+
|                  ACME Server                       |
|  +----------------------------------------------+  |
|  |              Application Layer               |  |
|  |   ACME API | Admin API | Health | Metrics   |  |
|  +---------------------+------------------------+  |
|                         |                          |
|  +---------------------v------------------------+  |
|  |           QRDB (Embedded KV Storage)          |  |
|  |  +------------------------------------------+ |  |
|  |  |  KV Store          |   Seal/Unseal        | |  |
|  |  +------------------------------------------+ |  |
|  |                      |                        |  |
|  |  +-------------------v---------------------+  |  |
|  |  |           PebbleDB (Direct)              |  |  |
|  |  +-----------------------------------------+  |  |
|  +----------------------------------------------+  |
|                                                    |
|  +----------------------------------------------+  |
|  |  QRDB RBAC (Policy Engine, Auth)              |  |
|  +----------------------------------------------+  |
|                                                    |
|  +----------------------------------------------+  |
|  |               Key Storage                     |  |
|  |    go-xkms: Software | TPM | HSM | KMS       |  |
|  +----------------------------------------------+  |
+----------------------------------------------------+
```

**Configuration:**
```yaml
qrdb:
  mode: standalone
  data_dir: /var/lib/xkms/data
  cluster_id: 1
  node_id: 1
```

### Mode 2: Raft (Single-Node)

Single-node deployment with Raft consensus. Identical to standalone but prepared for future cluster expansion.

```
+----------------------------------------------------+
|                  ACME Server                       |
|  +----------------------------------------------+  |
|  |              Application Layer               |  |
|  |   ACME API | Admin API | Health | Metrics   |  |
|  +---------------------+------------------------+  |
|                         |                          |
|  +---------------------v------------------------+  |
|  |           QRDB (Embedded KV Storage)          |  |
|  |  +------------------------------------------+ |  |
|  |  |  KV Store          |   Seal/Unseal        | |  |
|  |  +------------------------------------------+ |  |
|  |                      |                        |  |
|  |  +-------------------v---------------------+  |  |
|  |  |       Raft Consensus (Single Node)       |  |  |
|  |  |            QRDB Raft                     |  |  |
|  |  +-------------------+---------------------+  |  |
|  |                      |                        |  |
|  |  +-------------------v---------------------+  |  |
|  |  |              PebbleDB                    |  |  |
|  |  +-----------------------------------------+  |  |
|  +----------------------------------------------+  |
|                                                    |
|  +----------------------------------------------+  |
|  |  QRDB RBAC (Policy Engine, Auth)              |  |
|  +----------------------------------------------+  |
+----------------------------------------------------+
```

**Configuration:**
```yaml
qrdb:
  mode: raft
  data_dir: /var/lib/xkms/data
  cluster_id: 1
  node_id: 1
  raft:
    listen_addr: "0.0.0.0:2380"
    # No peers = single-node Raft
```

### Mode 3: Cluster (Multi-Node Raft HA)

Multi-node deployment with Raft consensus for high availability and automatic failover.

```
                              +---------------------+
                              |   Load Balancer     |
                              |  (nginx/HAProxy)    |
                              +---------+-----------+
                                        |
          +-----------------------------+-----------------------------+
          |                             |                             |
+---------v---------+         +---------v---------+         +---------v---------+
|   ACME Server 1   |         |   ACME Server 2   |         |   ACME Server 3   |
|     (Leader)      |         |    (Follower)     |         |    (Follower)     |
+-------------------+         +-------------------+         +-------------------+
|  QRDB Embedded   |<------->|  QRDB Embedded   |<------->|  QRDB Embedded   |
|  +-------------+  |  Raft   |  +-------------+  |  Raft   |  +-------------+  |
|  |  KV Store   |  | <-----> |  |  KV Store   |  | <-----> |  |  KV Store   |  |
|  +-------------+  |         |  +-------------+  |         |  +-------------+  |
|  |  PebbleDB   |  |         |  |  PebbleDB   |  |         |  |  PebbleDB   |  |
|  +-------------+  |         |  +-------------+  |         |  +-------------+  |
+-------------------+         +-------------------+         +-------------------+
        |                             |                             |
        |                             |                             |
+-------v-----------------------------v-----------------------------v-------+
|                        Key Storage (per node)                             |
|      go-xkms: Software | TPM 2.0 | PKCS#11 | AWS | GCP | Azure        |
+---------------------------------------------------------------------------+
```

**Configuration (Node 1):**
```yaml
qrdb:
  mode: raft
  data_dir: /var/lib/xkms/data
  cluster_id: 1
  node_id: 1
  raft:
    listen_addr: "0.0.0.0:2380"
    advertise_addr: "node1.example.com:2380"
    peers:
      - node_id: 1
        addr: "node1.example.com:2380"
      - node_id: 2
        addr: "node2.example.com:2380"
      - node_id: 3
        addr: "node3.example.com:2380"
```

## Component Architecture

### Application Layer

```
+---------------------------------------------------------------------------+
|                           Public Interfaces                                |
|  +------------------+  +------------------+  +--------------------------+  |
|  |    ACME API      |  |    Admin API     |  |   Health & Metrics       |  |
|  |   (RFC 8555)     |  |     (REST)       |  |  /health | /metrics      |  |
|  +--------+---------+  +--------+---------+  +------------+-------------+  |
+----------+-----------------------+-------------------------+---------------+
|                             Service Layer                                  |
|  +------------------+  +------------------+  +--------------------------+  |
|  |   Certificate    |  |     Tenant       |  |       Policy             |  |
|  |    Authority     |  |    Service       |  |       Engine             |  |
|  +--------+---------+  +--------+---------+  +------------+-------------+  |
+----------+-----------------------+-------------------------+---------------+
|                       Storage & Auth Integration                           |
|  +------------------+  +------------------+  +--------------------------+  |
|  |  QRDB KV Store   |  |  QRDB RBAC/IAM  |  |      go-xkms KMS        |  |
|  |  (Accounts,      |  |   (Policies,     |  |   (Tenant Keys,          |  |
|  |   Orders, etc)   |  |    Roles, Auth)  |  |    Certificates)         |  |
|  +------------------+  +------------------+  +--------------------------+  |
+----------------------------------------------------------------------------+
|                           Storage Backends                                 |
|  +---------------------------------------------------------------------+  |
|  |  Keys: go-xkms (Software|TPM|PKCS#11|AWS|GCP|Azure|Vault)          |  |
|  |  Data: go-objstore (Local|S3|GCS|Azure Blob)                        |  |
|  +---------------------------------------------------------------------+  |
+----------------------------------------------------------------------------+
```

### ACME Server Layer

The ACME server implements RFC 8555 with extensions for device attestation.

```
pkg/acme/
+-- server/
|   +-- handlers/           # HTTP handlers for ACME endpoints
|   |   +-- directory.go    # GET  /directory
|   |   +-- new_nonce.go    # HEAD /new-nonce
|   |   +-- new_account.go  # POST /new-account
|   |   +-- new_order.go    # POST /new-order
|   |   +-- authorization.go
|   |   +-- challenge.go
|   |   +-- order_finalize.go
|   |   +-- certificate.go
|   +-- middleware/         # JWS validation, nonce handling
|   +-- rate_limiter.go     # RFC 8555 Section 6.6 compliance
+-- challenges/
|   +-- http-01/            # HTTP domain validation
|   +-- dns-01/             # DNS domain validation
|   +-- device-attest-01/   # TPM attestation (RFC 8823)
|   +-- enroll-01/          # TPM enrollment (TCG 6.2)
|   +-- endorse-01/         # EK certificate issuance
+-- client/                 # ACME client implementation
+-- entities/               # Domain entities
+-- storage/                # Storage interfaces
```

### Certificate Authority Layer

```
pkg/ca/
+-- ca.go                   # Main CA implementation
+-- signing.go              # Certificate signing
+-- crl.go                  # CRL generation
+-- ocsp.go                 # OCSP responder
+-- attestation.go          # TPM attestation verification
+-- cross_signing.go        # Cross-signing support
+-- tpm_certificates.go     # TPM certificate handling
+-- config.go               # CA configuration
+-- types.go                # CA types and interfaces
```

### Storage Layer

All KV storage is handled through QRDB with tenant-scoped key prefixes. RBAC policy storage is also in QRDB.

```
pkg/qrdb/
+-- service_provider.go     # Lifecycle management (init, seal/unseal, shutdown)
+-- interface.go            # Service interface (KV, Seal)
+-- provider.go             # ServiceProvider implementation
+-- kv.go                   # KVClient interface
+-- kv_memory.go            # In-memory KV for testing
+-- seal/                   # Seal adapter for Shamir's Secret Sharing
|   +-- adapter.go
+-- dao/                    # DAO implementations using QRDB KV
|   +-- factory.go          # TenantAwareFactory for tenant-scoped DAOs
|   +-- generic.go          # Generic DAO with tenant key prefixes
|   +-- account.go          # ACME account storage
|   +-- order.go            # Certificate order storage
|   +-- authorization.go    # Domain authorization storage
|   +-- challenge.go        # ACME challenge storage
|   +-- certificate.go      # Issued certificate storage
|   +-- nonce.go            # Replay nonce storage
|   +-- tenant.go           # Tenant management
|   +-- external_account_binding.go  # EAB storage
+-- objstore/               # go-objstore adapter for blob storage
    +-- adapter.go          # Storage interface backed by QRDB KV

pkg/auth/
+-- interface.go            # AuthClient interface (QRDB Auth)
+-- client.go               # Auth client implementation

pkg/acme/storage/
+-- types.go                # DAO interfaces (implemented by qrdb/dao)
+-- errors.go               # Storage errors
```

#### Import Guidance

All QRDB types are accessed through the go-qrdb SDK:

```go
import (
    // QRDB SDK for KV storage, IAM, auth, lifecycle
    qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

    // QRDB transport types (KVClient, Transport, DatabaseError, etc.)
    "github.com/jeremyhahn/go-qrdb/sdk/go/db"

    // System utilities (OpenSSL config parsing)
    "github.com/jeremyhahn/go-qrdb/pkg/system"
)

// Use db.KVClient, db.Transport, db.DatabaseError, etc.
// Use system.LoadOpenSSLConfig() for OpenSSL defaults
```

#### Key Hierarchy in QRDB

All data uses tenant-scoped key prefixes for isolation:

```
tenant/{tenant_id}/account/{account_id}
tenant/{tenant_id}/order/{account_id}/{order_id}
tenant/{tenant_id}/authz/{account_id}/{authz_id}
tenant/{tenant_id}/challenge/{account_id}/{challenge_id}
tenant/{tenant_id}/certificate/{fingerprint}
tenant/{tenant_id}/nonce/{nonce}
tenant/{tenant_id}/eab/{mac_key_id}
global/tenant/{tenant_id}
```

## Key Storage Backends

The ACME server uses go-xkms's key-storage backends for secure key storage, with multiple backend options:

| Backend | Description | Security Level |
|---------|-------------|----------------|
| Software (PKCS#8) | File-based encrypted keys | Basic |
| TPM 2.0 | Hardware-bound keys on device | High |
| PKCS#11/HSM | Enterprise HSMs (Luna, nCipher, SoftHSM) | Very High |
| AWS KMS | AWS Key Management Service | High |
| GCP Cloud KMS | Google Cloud Key Management | High |
| Azure Key Vault | Azure Key Vault | High |
| HashiCorp Vault | Multi-cloud secret management | High |

## Data Flow

### Certificate Issuance Flow

```
Client                  ACME Server              CA                  Storage
  |                         |                     |                     |
  +--POST /new-account----->|                     |                     |
  |                         +--Create Account---->|                     |
  |<--------Account---------+                     |                     |
  |                         |                     |                     |
  +--POST /new-order------->|                     |                     |
  |                         +--Create Order------>|                     |
  |<--------Order-----------+                     |                     |
  |                         |                     |                     |
  +--GET /authz/{id}------->|                     |                     |
  |<---Authorization--------+                     |                     |
  |                         |                     |                     |
  +--POST /challenge/{id}-->|                     |                     |
  |                         +--Validate---------->|                     |
  |<---Challenge Status-----+                     |                     |
  |                         |                     |                     |
  +--POST /order/finalize-->|                     |                     |
  |                         +--Sign Certificate-->|                     |
  |                         |                     +--Store Cert-------->|
  |<--------Order-----------+                     |                     |
  |                         |                     |                     |
  +--GET /cert/{id}-------->|                     |                     |
  |<--------Certificate-----+                     |                     |
```

### TPM Enrollment Flow (enroll-01)

```
Device                  ACME Server              CA                   TPM
  |                         |                     |                     |
  |<-------------------------------------------------Get EK Cert------>|
  |                         |                     |                     |
  +--POST /new-account----->|                     |                     |
  |   (with EAB)            |                     |                     |
  |<--------Account---------+                     |                     |
  |                         |                     |                     |
  +--POST /new-order------->|                     |                     |
  |   (permanent-identifier)|                     |                     |
  |<--------Order-----------+                     |                     |
  |                         |                     |                     |
  +--POST /challenge/{id}-->|                     |                     |
  |                         +--MakeCredential---->|                     |
  |<---Encrypted Blob-------+                     |                     |
  |                         |                     |                     |
  +--ActivateCredential--------------------------------------------------->|
  |<---Decrypted Secret-----------------------------------------------------+
  |                         |                     |                     |
  +--POST /challenge/{id}-->|                     |                     |
  |   (with secret)         |                     |                     |
  |<----Challenge Valid-----+                     |                     |
```

## Security Architecture

### Key Hierarchy

```
+---------------------------------------------------------------------------+
|             Sealed Master Key (Shamir's Secret Sharing)                    |
|                         Threshold: 2-of-3                                 |
+-------------------------------+-------------------------------------------+
                                |
                                v
+-------------------------------+-------------------------------------------+
|                    Cluster Data Encryption Key                             |
|                     (Encrypts Global Data)                                |
+----------------------------------------------------------------------------+
|  Global Root CA Key                                                        |
|  Global Intermediate CA Key                                                |
+-------------------------------+-------------------------------------------+
                                |
           +--------------------+--------------------+
           v                    v                    v
+-------------------+ +-------------------+ +-------------------+
|   Tenant A DEK    | |   Tenant B DEK    | |   Tenant C DEK    |
+-------------------+ +-------------------+ +-------------------+
| - Root CA Key     | | - Root CA Key     | | - Root CA Key     |
|   (optional)      | |   (optional)      | |   (optional)      |
| - Intermediate    | | - Intermediate    | | - Intermediate    |
|   CA Key          | |   CA Key          | |   CA Key          |
| - Tenant Data     | | - Tenant Data     | | - Tenant Data     |
|   (encrypted)     | |   (encrypted)     | |   (encrypted)     |
+-------------------+ +-------------------+ +-------------------+
```

### Authentication & Authorization

| Component | Authentication | Authorization |
|-----------|----------------|---------------|
| ACME API | JWS signatures | Account-based |
| Admin API | Bearer tokens (JWT) or mTLS | go-qrdb RBAC |
| QRDB IAM | JWT tokens | RBAC policies |

### Roles

| Role | Scope | Capabilities |
|------|-------|--------------|
| so | Own tenant; all tenants from the system tenant | CA hierarchy, ACME administration, barrier governance, role management |
| admin | Own tenant; all tenants from the system tenant | Tenant, CA hierarchy, user, certificate, and EAB lifecycle |
| operator | Own tenant | Read-only ACME registration data and CA hierarchy |
| user | Own tenant | No ACME administration |
| auditor | Own tenant | Read-only metadata plus the audit trail |
| custodian | Own tenant | `barrier:unseal-share` only |

These are go-qrdb's canonical roles. The Admin API defines none of its own;
cross-tenant reach follows qrdb's system-tenant rule rather than a role level:
an identity rooted in the reserved system tenant, or one carrying no tenant at
all (empty `TenantID`), reaches every tenant (`auth.IsCrossTenant`).

## API Endpoints

### ACME API (RFC 8555)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/acme/directory` | GET | Directory metadata |
| `/acme/new-nonce` | HEAD/GET | Get replay nonce |
| `/acme/new-account` | POST | Create account |
| `/acme/new-order` | POST | Create certificate order |
| `/acme/authz/{id}` | GET/POST | Authorization details |
| `/acme/challenge/{id}` | POST | Challenge response |
| `/acme/order/{id}/finalize` | POST | Finalize order with CSR |
| `/acme/cert/{id}` | GET | Download certificate |
| `/acme/revoke-cert` | POST | Revoke certificate |
| `/acme/key-change` | POST | Account key rollover |

### Admin API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/certificates` | GET | List certificates |
| `/admin/accounts` | GET | List accounts |
| `/admin/orders` | GET | List orders |
| `/admin/status` | GET | CA status |
| `/admin/stats` | GET | Statistics |
| `/api/v1/tenants` | CRUD | Tenant management |
| `/api/v1/tenants/{id}/eab` | CRUD | EAB management |
| `/api/v1/tenants/{id}/intermediate-cas` | CRUD | CA management |

## Configuration

See configuration examples:
- Single Node - standalone mode for development; see [`../acme-issuance/engineering.md`](../acme-issuance/engineering.md) §Configuration (`acme/configuration.md` was deleted by go-xkms#942) and the shipped `configs/xkmsd-local.yaml`
- Cluster - Raft cluster for production HA; see [qrdb/configuration.md](qrdb/configuration.md). No standalone `config.yaml` / `config-cluster.yaml` sample ships in this repository.
