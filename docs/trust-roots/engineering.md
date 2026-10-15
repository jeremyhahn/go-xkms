# Trust Roots — Engineering

> **Status: NORMATIVE** · Feature: `trust-roots` · Repo: `go-xkms` · Last verified: 2026-10-15

## Exported surface

`pkg/attestation/truststore`:

| Name | Where | Contract |
|---|---|---|
| `NewDAOStore(*qrdbsdk.DAOFactory) (*DAOStore, error)` | `dao_store.go:47` | opens the `trust_roots` database; a DAO failure is `ErrDAOCreation` |
| `(*DAOStore).Add` | `dao_store.go:75` | classifies with `ClassifyCertificate` unless `opts.Purpose` is set; a held certificate is `ErrCertificateExists` |
| `(*DAOStore).ImportPEM` | `dao_store.go:144` | adds every `CERTIFICATE` block; returns `ImportResult{Added, Skipped}`, held certificates counted as skipped |
| `(*DAOStore).SetPurpose` | `dao_store.go:163` | reclassifies one root; quarantine is `SetPurpose(…, PurposeSynced)` |
| `(*DAOStore).Anchors` | `dao_store.go:192` | the certificates of an anchor purpose; `ErrNotAnchorPurpose` for `synced` |
| `(*DAOStore).Get`, `GetByPurpose`, `List`, `Delete`, `Page`, `Close` | `dao_store.go:201-327` | read, filter, list, remove, cursor-page, close |
| `ClassifyCertificate` | `classify.go:61` | purpose from the certificate's contents |
| `ParsePurpose`, `IsValidPurpose`, `IsAnchorPurpose` | `types.go:75-89` | the taxonomy checks |
| `Fingerprint` | `truststore.go:116` | lowercase hex SHA-256 of the DER certificate |

`pkg/xkms`: `SetTrustRootStore`, `TrustRootStore` and the five
`TrustRoot*` methods (`servicer_trust_roots.go:32-140`), the
`transport.TrustRootServicer` contract (`pkg/api/transport/servicer.go:278`).

`pkg/compose`: `BuildTrustRootStore` (`builders.go:106`), feature
`FeatureTrustRoots` (`errors.go:73`), `Stores.TrustRoots`
(`compose.go:155`).

`sdk/go`: type aliases `TrustRoot`, `TrustRootRequest`,
`TrustRootListRequest`, `TrustRootListResponse`, `TrustRootImportRequest`,
`TrustRootImportResponse` (`xkms.go:565-570`, `transport/types.go:277-282`)
and `transport.TrustRootService` (`transport/client.go:38`).

## Invariants

- A fingerprint is 64 lowercase hex characters (`validateFingerprint`,
  `file.go:724`); anything else is `ErrInvalidFingerprint` before the store is
  read.
- One entity per certificate: the entity ID is derived from the fingerprint,
  so a second import of the same DER is skipped, never duplicated, and keeps
  its purpose.
- Every verb checks the caller is platform-scoped before the store is
  consulted, so an unwired store and a tenant caller cannot be told apart by a
  tenant.
- The store is held in an atomic pointer on `XKMSService`; wiring it is safe
  while serving.
- After `Close` every operation returns `ErrStoreClosed`.

## Error semantics

One table, `apierrors.TrustRootSentinelClasses`
(`pkg/api/apierrors/tables.go:110-123`), maps every error for every transport:

| Error | Class | REST | gRPC | MCP |
|---|---|---|---|---|
| `xkms.ErrNotConfigured`, `truststore.ErrStoreClosed` | Unavailable | 503 | `Unavailable` | service unavailable |
| `xkms.ErrNilRequest`, `ErrInvalidCertificate`, `ErrInvalidFingerprint`, `ErrInvalidPurpose` | InvalidArgument | 400 | `InvalidArgument` | invalid params |
| `ErrCertificateNotFound` | NotFound | 404 | `NotFound` | not found |
| `ErrCertificateExists` | AlreadyExists | 409 | `AlreadyExists` | duplicate |
| tenant-scoped caller (`*xkms.TenantBindingError`, unwraps to `qrdbsdk.ErrTenantMissing`) | NotFound | 404 | `NotFound` | not found |

A malformed REST import body is 400 before the service is called. Anything
unclassified is an internal error.

## Configuration

None. The store is composed whenever the node has a DAO factory; its database
`trust_roots` is in `compose.Databases`.

## Persistence

Database `trust_roots`, entity type `trust_certs` (`TrustCertEntity`,
`entity.go:20`): fingerprint, purpose, subject, issuer, algorithm, validity,
PEM, source and added-at. No migration: the store starts empty.

## Permissions

`trust_roots` (`pkg/auth/permissions.go:123`) with `list`, `get`, `import`,
`update` (quarantine) and `delete`. xkms owns the names and declares each
`ScopeCross` (`pkg/apimodule/module_scopes.go:142-149`). They are granted to
go-qrdb's built-in Admin and Owner roles with the other module permissions
(`module_grants.go:81-82`), not to User.

## Test strategy

- `pkg/attestation/truststore`: the moved store, import, classification and
  quarantine tests, run over `testutil.NewMemoryDAOFactory()`.
- `pkg/xkms/servicer_trust_roots_test.go`: DAO round trip, a duplicate
  import keeping its purpose, quarantine refusal (`Anchors(synced)`), bad
  input, tenant refusal, unwired store.
- `pkg/api/grpc`, `pkg/api/rest`: each verb through its handler, and the
  error mapping table above.
- The authorization golden tables in `pkg/api/grpc`, `pkg/api/rest` and
  `pkg/api/mcp`, and `pkg/api/authz_consistency_test`, pin the permission of
  every verb on every transport.
- `pkg/compose`: the store is built and wired when DAOs exist, and its absence
  is typed when they do not.
