# Backup — Engineering Contract

> **Status: NORMATIVE** · Feature: `backup` · Repo: `go-xkms` · Last verified: 2026-09-30

## Exported surface

### Service layer — `pkg/xkms`

```go
// pkg/xkms/service.go
func (s *XKMSService) SetBackupClient(c qrdbtransport.BackupClient)

// pkg/xkms/servicer_backup.go
type BackupServicer interface {
	CreateBackup(ctx context.Context, req *transport.BackupRequest) (*transport.BackupInfo, error)
	ListBackups(ctx context.Context) ([]transport.BackupInfo, error)
	GetBackup(ctx context.Context, id string) (*transport.BackupInfo, error)
	DeleteBackup(ctx context.Context, id string) error
	RestoreBackup(ctx context.Context, req *transport.RestoreRequest) (*transport.RestoreResult, error)
	VerifyBackup(ctx context.Context, id string) (*transport.VerifyResult, error)
}
```

`XKMSService` implements `BackupServicer` as a direct pass-through to
whatever `qrdbtransport.BackupClient` was last wired by `SetBackupClient`.
Every method returns `xkms.ErrNotConfigured` when no client has been wired,
and `CreateBackup`/`RestoreBackup` return `xkms.ErrNilRequest` for a nil
request — the same two guards every other node-pass-through servicer in this
package uses (compare `servicer_custodian.go`).

### Transport types — `pkg/api/transport/types_backup.go`

Direct type aliases of `go-qrdb/sdk/go/transport`, not go-xkms types:

```go
type BackupRequest       = qrdbtransport.BackupRequest
type BackupInfo          = qrdbtransport.BackupInfo
type RestoreRequest      = qrdbtransport.RestoreRequest
type RestoreResult       = qrdbtransport.RestoreResult
type VerifyResult        = qrdbtransport.VerifyResult
type ShardError          = qrdbtransport.ShardError
type ListBackupsResponse = qrdbtransport.ListBackupsResponse
type CompressionType     = qrdbtransport.CompressionType // "none" | "zstd" | "snappy"
type EncryptionType      = qrdbtransport.EncryptionType  // "none" | "aes256"
type BackupStatus        = qrdbtransport.BackupStatus    // pending|running|complete|failed
```

Aliasing rather than redeclaring means a field added to go-qrdb's wire shape
appears here automatically, with no translation step that could silently
drop it.

### Wiring — `pkg/compose`, `pkg/server`, `pkg/apimodule`

`compose.Deps.Backup` / `compose.Stores.Backup` carry a
`qrdbtransport.BackupClient` through the same `Build`/`Wire` composition
every other store-backed feature uses (`FeatureBackup`). Unlike
`Custodians`/`Shares`, it is **not** gated on `ServeBarrier` — whole-node
backup has no barrier-custody dependency, so it composes whenever the host
qrdb client exists.

```go
// pkg/server/server.go (xkmsd daemon)
stores.Backup = s.qrdbClient.Backup()

// pkg/apimodule/module_host.go (embedding host, e.g. go-quicbaas)
deps.Backup = client.Backup()
```

`client.Backup()` is `*qrdbsdk.Client`'s own accessor
(`go-qrdb/sdk/go/backup.go`); it returns `nil` when the active transport does
not implement `transport.BackupClient`, which `compose.Build`'s `b.need`
guard treats like any other missing dependency (`FeatureDisabledError`,
reason `"backup client"`).

## Invariants

- **xkms performs no shard capture, checksum computation, compression or
  encryption.** Every one of those happens inside the go-qrdb node this
  process embeds.
- **Nil-safety is structural, not defensive.** `s.backup.load()` returning
  `nil` is the only "not configured" signal; there is no secondary check.
- **Restore and verify never run without an explicit request naming a
  backup ID.** There is no "restore the latest backup" shortcut — the ID is
  always the caller's.
- **`ValidateFirst` on restore is the caller's choice, not a default.**
  Setting it runs a checksum verification before touching any shard and
  aborts the restore on mismatch (`BackupChecksumMismatchError`); leaving it
  unset restores without that check. `backup verify` run as its own call
  never mutates state.
- **Permission is per-operation, never bundled.** Create, list, get, delete,
  restore and verify each carry their own go-qrdb `backup:*` grant; holding
  one implies none of the others.

## Error semantics

Every error returned by the embedded node surfaces to the caller unmodified
in type, mapped (not rewritten) to each transport's native shape:

| go-qrdb transport error | REST | gRPC | MCP |
|---|---|---|---|
| `*transport.BackupNotFoundError` | 404 | `NotFound` | `-32001` |
| `*transport.BackupEmptyDestinationError` | 400 | `InvalidArgument` | `-32602` |
| `*transport.BackupEmptyIDError` | 400 | `InvalidArgument` | `-32602` |
| `*transport.BackupChecksumMismatchError` | 409 | `FailedPrecondition` | `-32603` |
| `*transport.BackupCreateError` / `*BackupRestoreError` / `*BackupVerifyError` (wraps the underlying cause, including a standalone node's `BackupUnsupportedError`) | 500 | `Internal` | `-32603` |
| `xkms.ErrNotConfigured` (no backup client wired) | 503 | `FailedPrecondition` | `-32004` |
| `xkms.ErrNilRequest` | 400 | `InvalidArgument` | `-32602` |

A standalone node's refusal (`BackupUnsupportedError`, raised inside
go-qrdb's own shard-snapshot provider) is never special-cased by xkms: it
arrives wrapped in a `*transport.BackupCreateError`/`*BackupRestoreError` and
is reported through the same generic-failure path as any other create/restore
error, with the underlying message intact so an operator can tell the two
apart.

## Configuration

Nothing is configured at the xkms layer. Every knob — destination,
compression, encryption, encryption key, target shards, validate-first,
decryption key — is a field on the request the caller sends; xkms applies no
defaults of its own beyond what the aliased `BackupRequest`/`RestoreRequest`
zero values mean to go-qrdb (empty compression/encryption means `none`).

## Permission model

One go-qrdb permission per verb, declared in `pkg/auth/permissions.go`
(`ResourceBackup = "backup"`, `ActionRestore = "restore"`; the other five
actions — `create`, `list`, `get`→mapped to qrdb's canonical `read`,
`delete`, `verify` — already existed) and enforced identically on every
transport:

| Verb | Permission |
|---|---|
| Create | `backup:create` |
| List | `backup:list` |
| Get | `backup:read` |
| Delete | `backup:delete` |
| Restore | `backup:restore` |
| Verify | `backup:verify` |

These mirror go-qrdb's own canonical `permission.Backup*` family
(`pkg/permission/constants.go`) verbatim and inherit its `ScopeSelf`
declaration — a grant reaches only the holder's own tenant, lifted
cluster-wide for a system-tenant identity — so `pkg/auth/permissions.go`
declares no local tenancy scope for `backup` (see that file's header comment
for which resources *do* need a local scope declaration and why `backup`
does not). The built-in system/tenant Admin roles hold the family by default,
as they hold every other qrdb-canonical permission family.

Four cross-transport consistency tests enforce that the table above cannot
drift: `pkg/api/rest/authz_golden_test.go`
(`TestRESTPermissions_MatchWireContract`), `pkg/api/grpc/authz_golden_test.go`
(`TestRPCPermissions_MatchWireContract` and
`TestRPCPermissions_ProtoOptionMatchesGoldenTable`),
`pkg/api/mcp/authz_test.go` (`TestMethodPermissions_ScanMatchesWireContract`,
`TestMethodPermissions_MatchOtherTransports`), and
`pkg/api/authz_consistency_test` (`TestCapabilities_RequireSamePermissionOnEveryTransport`).

## Test strategy

- **Unit (service layer)** — `pkg/xkms/servicer_backup_test.go`: a
  `fakeBackupClient` implementing `qrdbtransport.BackupClient` in memory,
  with a genuine SHA-256 checksum over simulated shard payload so a test can
  tamper the stored bytes and observe a real mismatch. Covers every
  `ErrNotConfigured`/`ErrNilRequest` guard, every success path, not-found,
  empty-destination, and both the checksum-mismatch-on-verify and
  refuse-to-restore-a-tampered-backup-when-validated cases.
- **Authorization** — `pkg/api/rest/server_route_authz_test.go`'s
  `gatedRoutePermissions` table (`TestGatedRoutes_RBACDenied`,
  `TestGatedRoutes_RequirePermission`) proves each REST route 403s a caller
  denied the matching permission and succeeds for the correct one, through
  the real chi router and RBAC middleware. The golden tests listed under
  "Permission model" prove REST, gRPC and MCP agree on the grant.
- **Composition** — `pkg/compose/compose_test.go`'s `TestBuild_*` family and
  `pkg/apimodule/module_host_stores_test.go` prove `FeatureBackup` composes
  when a backup client is supplied and is off with a typed reason
  (`"backup client"`) when it is not, through both the `xkmsd` daemon's and
  an embedding host's wiring paths.
- **Fakes** — `pkg/testutil/qrdb_fake.go`'s `QRDBFakeTransport` implements
  `transport.BackupClient` with real (if simple) in-memory semantics, so
  "every dependency supplied" composition tests see backup genuinely on
  rather than stubbed out.
- **Not duplicated here** — go-qrdb's own test suite proves shard capture,
  checksum computation, compression and encryption correctness; this
  package does not re-prove them.

## Observability

No backup-specific instrumentation was added. A deployment that configures
an audit logger (`pkg/audit`) sees backup/restore calls the same way it sees
every other named route/RPC/JSON-RPC method on these transports; this
feature introduces no separate logging, metrics or tracing path.
