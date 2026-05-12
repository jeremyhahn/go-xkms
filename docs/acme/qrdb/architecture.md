# QRDB Architecture

## Layer Overview

```
API Layer
    |
Service Layer (pkg/qrdb.Service)
    |
    +-- db.SDKClient (go-qrdb SDK)
    |       |
    |       +-- db.KVClient
    |       +-- db.AdminClient
    |       +-- db.WatchClient
    |       +-- db.LeaseClient
    |       +-- db.BatchClient
    |       +-- db.TransactionClient
    |       +-- db.IndexClient
    |
    +-- KVStoreAdapter (db.KVClient -> qrdbsdk.QRDBKVStore)
    |
    +-- DAO Factory (dao.Factory)
            |
            +-- AccountDAO
            +-- OrderDAO (per account)
            +-- AuthorizationDAO (per account)
            +-- ChallengeDAO (per account)
            +-- CertificateDAO
            +-- NonceDAO
            +-- ExternalAccountBindingDAO
            +-- TenantDAO
```

All types above `db.*` are from `github.com/jeremyhahn/go-qrdb/sdk/go/db` and types prefixed `qrdbsdk.*` are from `github.com/jeremyhahn/go-qrdb/sdk/go`.

## Service Implementation

`service` wraps a `db.SDKClient` and delegates each subsystem call directly. Health and lifecycle are tracked with `atomic.Bool` fields (`healthy`, `closed`) for lock-free concurrent access. `Close()` uses `atomic.Bool.Swap` to guarantee idempotent shutdown.

## KVStore Adapter

`kvStoreAdapter` bridges `db.KVClient` to `qrdbsdk.QRDBKVStore`, enabling the DAO layer to work identically across embedded and remote protocols. Key behavior:

- `Get` translates `db.KeyNotFoundError` into `qrdbsdk.DatabaseError{Code: ErrNotFound}` to satisfy DAO expectations.
- `Scan` fetches all prefix-matched pairs via `db.KVClient.Scan` and iterates the returned map through the caller's callback.

## DAO Layer

### Factory Pattern

`dao.Factory` implements both `storage.Factory` and `storage.TenantAwareFactory`. It accepts a `qrdbsdk.QRDBKVStore` and a `storage.Codec` for serialization.

**Global scope:** `NewFactory(kvStore, codec)` creates DAOs without tenant isolation.

**Tenant scope:** `ForTenant(tenantID)` returns a new factory that prefixes all keys with `tenants/{tenantID}/`.

### Key Namespace

All entities are stored under structured key prefixes:

| Entity | Key Pattern |
|--------|-------------|
| Account | `[tenants/{tid}/]accounts/{id}` |
| Order | `[tenants/{tid}/]accounts/{aid}/orders/{id}` |
| Authorization | `[tenants/{tid}/]accounts/{aid}/authorizations/{id}` |
| Challenge | `[tenants/{tid}/]accounts/{aid}/challenges/{id}` |
| Certificate | `[tenants/{tid}/]certificates/{id}` |
| Nonce | `[tenants/{tid}/]nonces/{id}` |
| EAB | `[tenants/{tid}/]eab/{kid}` |
| Tenant | `tenants/{id}` |

### Entity Types

- **uint64-keyed entities** (Account, Order, Authorization, Challenge, Certificate, Nonce): Wrapped in `qrdbsdk.QRDBGenericDAO` via `qrdbsdk.NewDAO`.
- **string-keyed entities** (Tenant, ExternalAccountBinding): Stored directly via `qrdbsdk.QRDBKVStore` since they do not implement the QRDB `Entity` interface.

### TenantDAO

Manages tenant lifecycle. `Delete` performs a soft delete by setting `Status = TenantStatusDeleted` rather than removing the key. `List` supports optional status filtering. `ListActive` is a convenience wrapper.

### ExternalAccountBindingDAO

Stores ACME External Account Bindings keyed by `kid`. `GetByAccountID` performs a prefix scan to find a binding by its bound account ID, using a sentinel `stopScanError` for early termination.

## IAM Policy Storage

`IAMPolicyStorage` implements `pkgiam.PolicyStorage` using QRDB KV. Gated behind the `iam` build tag.

- Key pattern: `iam/policies/{tenantID}/{policyName}`
- Policies are JSON-serialized.
- `ListPolicies` supports sorting by priority (default, descending), name, created, or updated, with offset/limit pagination.

### Typed Errors

- `PolicyAlreadyExistsError` -- CreatePolicy when key already exists.
- `PolicyNotFoundError` -- GetPolicy/UpdatePolicy when key is missing.
- `PolicySerializationError` -- JSON marshal/unmarshal failures, wraps cause via `Unwrap()`.

## Error Handling

All errors are typed. The `qrdbsdk.DatabaseError` struct carries:

- `Code` (`ErrorCode`) -- Categorizes the error (14 codes defined).
- `Message` -- Human-readable description.
- `Cause` -- Optional wrapped error, supports `errors.Unwrap`.
- `Context` -- Optional key-value debugging metadata.

Convenience checkers: `IsNotFound`, `IsAlreadyExists`, `IsConnection`, `IsSealed`, `IsNoLeader`, etc.

Standard sentinel errors such as `qrdbsdk.ErrNotFound` are used for common conditions.

DAO errors use value types: `NilEntityError`, `InvalidIDError`, `NilKVStoreError`.
