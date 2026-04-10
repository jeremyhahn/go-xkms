# ROADMAP: xkey as PKCS#11 Token and go-xkms Authenticator

Progress tracker for the multi-phase implementation plan.

## Part 1: PKCS#11 Token (IPC Transport)

### Phase 1: Extend IPC Protocol
- [ ] Add PKCS#11 message types to `xkey/pkg/ipc/protocol.go`
- [ ] Create `xkey/pkg/ipc/pkcs11_types.go` (SignParams, SignResult, PIV types, BarrierStatusResult)
- [ ] Add PKCS11Handler interface to `xkey/pkg/ipc/server.go`
- [ ] Update `xkey/pkg/ipc/errors.go` with new error types
- [ ] Tests for protocol extension

### Phase 2: IPCTransport
- [ ] Create `xkey/pkg/pkcs11/ipc_transport.go` implementing PKCS11Transport
- [ ] IPC-only connection (no fallback), 10s timeout, XKEY_IPC_SOCKET env var
- [ ] MVP operations: Sign, GetPIVCertificate, ListPIVSlots
- [ ] Tests for IPCTransport

### Phase 3: xkey PKCS#11 IPC Handler
- [ ] Create `xkey/pkg/gui/services/pkcs11_ipc_handler.go`
- [ ] Implement ipc.PKCS11Handler delegating to EmbeddedTransport
- [ ] Barrier seal status check before operations
- [ ] Tests for handler

### Phase 4: Integration
- [ ] Update `xkey/cmd/pkcs11-module/exports.go` to use IPCTransport
- [ ] Update `xkey/pkg/gui/app.go` to register PKCS11Handler (DIRECT EDIT ONLY)
- [ ] Update `xkey/cmd/xkey/cmd/fido2.go` for PKCS#11 IPC

### Phase 5: Testing & Docs
- [ ] Integration test: `xkey/test/integration/pkcs11/ipc_test.go`
- [ ] Documentation: `docs/pkcs11/browser-integration.md`

---

## Part 2: Roles, Custodians & Multi-Tenant Barriers

### Phase 6: Custodian Role + Tenant-Scoped Groups
- [x] Add `RoleCustodian` to `pkg/user/types.go`
- [x] Add `TenantID` field to User struct
- [x] Add `Roles []Role` field for multi-role support
- [x] Add `CanParticipateCeremony()` method
- [x] Update `pkg/rbac/memory.go` with custodian default role
- [x] Add custodian permissions: `barrier:provide-share`, `barrier:receive-share`
- [x] Add `ResourceBarrier` constant to RBAC
- [x] Create `pkg/custodian/types.go` (CustodianGroup, CustodianMember)
- [x] Create `pkg/custodian/store.go` (CustodianGroupStore interface)
- [x] Create `pkg/custodian/memory_store.go` (in-memory implementation)
- [x] Create `pkg/custodian/errors.go`
- [x] Create `pkg/custodian/service.go` (business logic)
- [x] Tests: types, store, service, error handling
- [x] Update `pkg/user/types_test.go` for new role

### Phase 7: Per-Tenant Barriers
- [x] Create `pkg/seal/tenant_barrier.go` (TenantBarrier wrapping tenant storage)
- [x] Create `pkg/seal/barrier_registry.go` (BarrierRegistry: system + tenant barriers)
- [x] Add TenantBarrierConfig to `pkg/seal/config.go`
- [x] Update `pkg/server/server.go` to use BarrierRegistry
- [x] Update `pkg/storage/namespace.go` to route through tenant barrier
- [x] Single-tenant backward compatibility (no tenant config = current behavior)
- [x] Tests for tenant barrier, registry, backward compat

### Phase 8: Local Shamir Backup (DR)
- [x] Add backup quorum support to CustodianGroup (Purpose: "backup")
- [x] Enforce backup quorum members differ from primary quorum
- [x] Backup activation generates audit alert + requires admin approval
- [x] Configuration: `--backup-threshold`, `--backup-total`, `--backup-custodians`
- [x] Tests for DR backup/recovery flow

### Phase 9: External Key Escrow
- [ ] Create `pkg/escrow/types.go` (EscrowAgent interface, EscrowRequest/Receipt/Record)
- [ ] Create `pkg/escrow/errors.go`
- [ ] Create `pkg/escrow/kmip/client.go` using `github.com/ovh/kmip-go`
- [ ] Create `pkg/escrow/xkms/federation.go` (xkms-to-xkms wrapped key over mTLS)
- [ ] Key wrapping: AES-KW (RFC 3394) or RSA-OAEP before transmission
- [ ] Configuration: `escrow:` section in YAML config
- [ ] Tests for escrow interface, KMIP client, federation

---

## Part 3: Bootstrap & Authentication

### Phase 10: Bootstrap Authentication
- [x] Create `pkg/server/bootstrap.go` (setup token generation, atomic init)
- [x] Create `pkg/api/rest/handlers_bootstrap.go` (`POST /api/v1/init`)
- [x] Setup token: JWT with TTL, one-time use
- [x] Atomic init: create admin + register FIDO2 + destroy token (all-or-nothing)
- [x] `--threshold` mode: ceremony with invitation tokens
- [x] Server first-boot output: setup token + SPKI pin + hostname
- [x] Tests for bootstrap flow, token lifecycle, threshold mode

### Phase 10a: Purge InsecureSkipVerify
- [x] SDK `WithTLSInsecureSkipVerify()` deprecated in favor of `WithSPKIPin`
- [x] `xkey cert request` requires `--spki-pin` or `--ca-file`
- [ ] Delete `WithTLSInsecureSkipVerify()` from `sdk/go/options.go`
- [ ] Remove from `sdk/go/transport/transport.go` Config struct
- [ ] Remove from `sdk/go/transport/rest/transport.go`
- [ ] Remove from `sdk/go/transport/grpc/transport.go`
- [ ] Remove from `sdk/go/transport/quic/transport.go`
- [ ] Remove from `sdk/go/transport/mcp/transport.go`
- [ ] Remove from `sdk/go/examples/mtls/main.go`
- [ ] Remove from `sdk/go/README.md`
- [ ] Remove from `cmd/xkmsctl/config.go`
- [ ] Remove from `xkey/pkg/gui/services/connection_service.go`
- [ ] Remove from `pkg/ca/tls.go`
- [ ] Remove from `docs/architecture/api-specifications.md`
- [ ] Update all test files to use proper test CA certs
- [ ] Replace `bootstrap_noise.go` InsecureSkipVerify with custom VerifyConnection + SPKI pin
- [ ] Update bootstrap docs

### Phase 11: FIDO2 Unified Auth (Browser + CLI)
- [x] CLI: `xkey auth register`, `xkey auth login`, `xkey auth status`, `xkey auth token`
- [ ] Create `pkg/webauthn/client/client.go` (headless WebAuthn client)
- [ ] Create `pkg/webauthn/client/ctap_adapter.go` (WebAuthn -> CTAP2 bridge via IPC)
- [ ] Create `pkg/webauthn/client/errors.go`
- [ ] GUI: `xkey/pkg/gui/services/auth_service.go`
- [ ] Tests for client, adapter, CLI commands

### Phase 12: Derived Client Cert + crypto.Signer
- [x] CLI: `xkey cert request --server=URL --slot=9a`
- [x] CLI: `xkey cert show`, `xkey cert export`
- [ ] Create `pkg/xkeysigner/signer.go` (crypto.Signer via IPC)
- [ ] Create `pkg/xkeysigner/tls.go` (TLSCertificate, TLSConfig helpers)
- [ ] Create `pkg/xkeysigner/errors.go`
- [ ] Tests for signer, TLS helpers

### Phase 13: SDK Integration
- [x] Add `WithSPKIPin(pin)` to `sdk/go/options.go`
- [ ] Add `WithXKeyAuth(socketPath)` to `sdk/go/options.go`
- [ ] PIV 9a cert available -> mTLS; otherwise -> FIDO2 -> JWT
- [ ] CA cert resolution from trust store by server URL
- [ ] Tests for SDK auth flow

### Phase 14: Configurable MFA Policy
- [ ] Create `pkg/auth/policy/types.go` (MFAPolicy, MFALevel, OperationPolicy)
- [ ] Create `pkg/auth/policy/engine.go` (policy evaluation)
- [ ] Create `pkg/auth/policy/errors.go`
- [ ] Per-operation: barrier_unseal, key_export, tenant_create can require 3FA
- [ ] Tests for policy engine, level evaluation

---

## Part 4: Key Share Management

### Phase 15: Key Share Store + Barrier Unsealing
- [x] Create `pkg/sharestore/types.go` (ShareStore interface, ShareEntry)
- [x] Create `pkg/sharestore/memory_store.go`
- [x] Create `pkg/sharestore/errors.go`
- [x] Create `xkey/pkg/gui/services/share_service.go`
- [x] CLI: `xkey share receive|import|unseal|list|delete`
- [x] Tests for share store, service, CLI
- [ ] Custodian enrollment: `xkmsctl custodian invite` -> `xkey auth enroll`

---

## Part 5: Unified Token Management & API Explorer

### Phase 16: Unified Token Service
- [x] Create `xkey/pkg/tokenstore/types.go` (TokenEntry, TokenStore interface)
- [x] Create `xkey/pkg/tokenstore/backend_store.go` (barrier-encrypted implementation)
- [x] Create `xkey/pkg/tokenstore/errors.go`
- [x] CLI: `xkey auth token --server=URL`, `xkey auth status`
- [ ] GUI: `xkey/pkg/gui/services/token_service.go`
- [x] Tests for token store, backend, CLI integration

### Phase 17: Server Registry
- [x] Create `xkey/pkg/serverregistry/types.go` (ServerEntry, ServerRegistry interface)
- [x] Create `xkey/pkg/serverregistry/backend_store.go` (barrier-encrypted)
- [x] Create `xkey/pkg/serverregistry/errors.go`
- [ ] CA cert resolution: URL -> ServerRegistry -> CAFingerprint -> Trust Store -> CA cert
- [x] Tests for registry, lookup flow

### Phase 18: API Explorer
- [ ] Create `xkey/pkg/gui/services/api_explorer_service.go`
- [ ] Go HTTP client with JWT injection from TokenStore
- [ ] TLS via Trust Store CA certs (auto-resolved by URL via Server Registry)
- [ ] Request history (barrier-encrypted)
- [ ] Frontend: `xkey/frontend/src/pages/APIExplorer.svelte`
- [ ] Tests for API explorer service

### Phase 19: Browser Settings
- [ ] Create `xkey/pkg/gui/services/browser_service.go` (BrowserConfig)
- [ ] Configurable browser: "system", custom path, custom command with {url}
- [ ] Config stored in `~/.xkey/config/browser.yaml` (plain, not barrier-encrypted)
- [ ] Replace hardcoded `browser.OpenURL()` with configurable launcher
- [ ] Tests for browser service

---

## Server-Side REST API

### Custodian REST Endpoints
- [x] `pkg/api/rest/handlers_custodian.go` -- Custodian group CRUD + member management + share distribution
- [x] `pkg/api/rest/handlers_share.go` -- Share submission, listing, status
- [x] `pkg/api/rest/handlers_tenant.go` -- Tenant CRUD + barrier operations

### xkmsctl CLI Commands
- [x] `cmd/xkmsctl/custodian.go` -- create, list, show, delete, add-member, remove-member, distribute
- [x] `cmd/xkmsctl/tenant.go` -- create, list, show, delete, barrier-init, barrier-unseal, barrier-status
- [x] `cmd/xkmsctl/bootstrap.go` -- Auto-bootstrap with DANE, Noise, SPKI priority

### SDK Client Methods
- [x] `sdk/go/transport/types.go` -- CustodianGroup, ShareEntry, Tenant request/response types
- [x] `sdk/go/transport/client.go` -- CustodianGroupService, ShareService, TenantService interfaces
- [x] `sdk/go/transport/rest/transport.go` -- REST implementations

### SPKI Pinning
- [x] `pkg/crypto/spki/spki.go` -- ComputePin, VerifyPin, FetchServerPin
- [x] `sdk/go/options.go` -- WithSPKIPin(pin string) Option
- [x] All SDK transports (REST, gRPC) verify SPKI pins

### GUI Services
- [x] `xkey/pkg/gui/services/share_service.go` -- ListShares, ImportShare, DeleteShare, ReceiveShares, SubmitShare
- [x] `xkey/pkg/gui/services/connection_service.go` -- SPKI pin support in Connect method
- [x] `xkey/pkg/gui/config.go` -- ServerSPKIPin config field

---

## Verification Checklist

- [ ] `pkcs11-tool --module ./libxkey_pkcs11.so --list-objects` shows 9a cert
- [ ] Firefox/Chrome client cert picker shows PIV 9a cert
- [x] `xkmsctl tenant create --name=acme --barrier-mode=shamir` works
- [ ] Tenant isolation enforced (cross-tenant access denied)
- [x] Single-tenant backward compatibility
- [x] `xkmsd` first boot prints setup token
- [x] `xkmsctl init --setup-token=<token>` configures system
- [x] `xkmsctl init --setup-token=<token> --threshold=3 --admins=5` works
- [x] `xkey auth register --server=URL` FIDO2 pairing works
- [x] `xkey share receive --server=URL` share distribution works
- [x] `xkey share unseal --server=URL` barrier unsealing works
- [ ] KMIP escrow agent sends/receives wrapped key material
- [ ] `grep -r "InsecureSkipVerify" .` returns ZERO matches
- [ ] All tests pass with proper test CA certs
- [x] `xkey auth token --server=URL` prints JWT
- [ ] API Explorer auto-populates JWT and executes requests
- [ ] All unit tests pass with 90%+ coverage
