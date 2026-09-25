# Roadmap

## Completed

### QRDB Storage + RBAC Integration

Storage and IAM are provided by QRDB (Raft-based distributed KV store with RBAC). Key management uses go-xkms directly.
- **KV Storage** - QRDB for all ACME entities, certificates, accounts
- **IAM** - QRDB RBAC PolicyEngine
- **Auth** - QRDB Auth for JWT token validation
- **KMS** - go-xkms for key management (TPM2, PKCS#11, PKCS#8)
- **Multi-tenancy** - Tenant isolation with scoped storage in QRDB

#### Completed Work

**ServiceProvider Pattern**
- [x] Created `pkg/qrdb/service_provider.go` for lifecycle management
- [x] Initialize/Shutdown with proper resource cleanup
- [x] Seal/Unseal support for production deployments
- [x] Configuration via `QRDBConfig`

**DAO Storage Layer**
- [x] Created `pkg/qrdb/dao/factory.go` - ACME storage factory
- [x] Account DAO - ACME account management
- [x] Order DAO - Certificate order management
- [x] Authorization DAO - Domain authorization
- [x] Challenge DAO - ACME challenges (HTTP-01, DNS-01, etc.)
- [x] Certificate DAO - Issued certificates
- [x] Nonce DAO - Replay protection
- [x] External Account Binding DAO - EAB support
- [x] Tenant DAO - Multi-tenant management

**Server Integration**
- [x] Server wired to use QRDB ServiceProvider
- [x] Storage factory uses QRDB DAOs
- [x] Configuration via Makefile BUILD_TAGS (`iam` tag required)

**Tenant Middleware**
- [x] Created `pkg/acme/server/handlers/middleware.go`
- [x] Multiple tenant extraction methods (header, subdomain, path)
- [x] Tenant validation and context propagation
- [x] `GetTenantScopedFactory` for tenant-scoped operations

**Blob Storage Adapter**
- [x] Created `pkg/qrdb/objstore/adapter.go`
- [x] Implements go-objstore `Storage` interface
- [x] Uses QRDB KV for blob storage
- [x] Full metadata support
- [x] Lifecycle policy management

**CA KMS Integration (go-xkms)**
- [x] Tenant CA signing key management via go-xkms (create, get, list, delete)
- [x] Key enable/disable operations
- [x] Certificate storage and retrieval
- [x] ACME handlers wired to use go-xkms KMS (`service.go`, `order_finalize.go`)
- [x] GetTenantCASigner uses go-xkms for tenant-specific signing

**Configuration Updates**
- [x] Updated `config/config.yaml` with QRDB configuration
- [x] Updated `config/config-raft.yaml` with Raft cluster config
- [x] Updated `config/config-cluster.yaml` with multi-node HA config
- [x] Updated `examples/config/server-config.yaml` with QRDB
- [x] Updated `examples/basic/config/server-config.yaml` with QRDB
- [x] Docker Compose configurations include QRDB cluster settings

---

## In Progress

### Raft Clustering

Full Raft cluster support for high availability:

- [ ] Instantiate Raft cluster from configuration
- [ ] Test multi-node deployment
- [ ] Leader election verification
- [ ] Automatic failover testing
- [ ] Documentation for clustered deployments

### CLI Testing

Comprehensive testing for `cactl` CLI:

- [ ] Add tests for all cactl commands
- [ ] Test via REST protocol
- [ ] Test via gRPC protocol
- [ ] Test via QUIC protocol
- [ ] Test via Unix Socket protocol
- [ ] Multi-protocol adapter pattern implementation

### Multi-Protocol Admin API

Feature parity across all protocols:

- [ ] REST API - Complete endpoint coverage
- [ ] gRPC API - Service definitions and handlers
- [ ] QUIC API - Transport implementation
- [ ] MCP API - Machine Control Protocol support
- [ ] Unix Socket API - Local IPC
- [ ] Protocol-specific integration tests

---

## Planned

### Production Hardening

- [x] Prometheus exporters for issuance/challenge/revocation/account events
      (`pkg/acme/server/metrics`, wired #734); see
      `docs/acme-issuance/engineering.md#observability`. Per-tenant
      rate-limit metrics remain unwired.
- [ ] Performance optimization and benchmarking
- [ ] Security audit and penetration testing
- [ ] Rate limiting per tenant
- [ ] Circuit breaker patterns
- [ ] Graceful degradation

### Documentation

- [ ] API reference documentation (OpenAPI/Swagger)
- [ ] gRPC API documentation (protobuf docs)
- [ ] Deployment guides (Docker, Docker Compose, bare metal)
- [ ] Operations runbooks
- [ ] Troubleshooting guide
- [ ] Performance tuning guide

### Future Enhancements

- [ ] Certificate Transparency (CT) log integration
- [ ] OCSP stapling improvements
- [ ] CRL distribution point automation
- [ ] Cross-signing workflow automation
- [ ] Key ceremony tooling
- [ ] HSM/TPM key storage via go-xkms
