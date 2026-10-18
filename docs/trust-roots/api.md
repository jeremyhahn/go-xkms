# Trust Roots — API

> **Status: NORMATIVE** · Feature: `trust-roots` · Repo: `go-xkms` · Last verified: 2026-10-15

Design: [`architecture.md`](architecture.md). Service: `XKMSService`
(`pkg/xkms/servicer_trust_roots.go`), which every transport calls.

## Tenancy

The store is platform state. Every operation is system-scope only
(`qrdbsdk.IdentityIsSystemTenant`, `pkg/xkms/servicer_trust_roots.go:42`): a tenant-scoped caller is refused with the
unknown-tenant not-found (`xkms.TenantBindingError`) before the store is read.

## Operations

| Operation | REST | gRPC / Unix (`KeystoreService.`) | MCP tool | Permission |
|---|---|---|---|---|
| List roots | `GET /api/v1/trust-roots[?purpose=]` | `TrustRootList` | `trust.root.list` | `trust_roots:list` |
| Get a root, PEM included | `GET /api/v1/trust-roots/{fingerprint}` | `TrustRootGet` | `trust.root.get` | `trust_roots:get` |
| Import a PEM bundle | `POST /api/v1/trust-roots` | `TrustRootImport` | `trust.root.import` | `trust_roots:import` |
| Quarantine a root (purpose `synced`) | `POST /api/v1/trust-roots/{fingerprint}/quarantine` | `TrustRootQuarantine` | `trust.root.quarantine` | `trust_roots:update` |
| Remove a root | `DELETE /api/v1/trust-roots/{fingerprint}` | `TrustRootRemove` | `trust.root.remove` | `trust_roots:delete` |

- Routes: `pkg/api/rest/routes.go:393-397`. RPCs:
  `pkg/api/grpc/proto/xkmsv1/xkms.proto:717-738`. MCP methods:
  `pkg/api/mcp/server.go:468-472`, each registered with its permission.
- QUIC serves the REST routes over HTTP/3; the embedded transport calls
  `XKMSService` directly. The USB transport (the xkey Android companion)
  answers `usb.ErrNotSupported` for the whole family.
- The client side is `transport.TrustRootService`, part of `transport.Client`
  (`pkg/api/transport/client.go:495`). The REST and QUIC clients share
  `wire.TrustRootClient`; the gRPC and Unix clients share
  `pbconv.TrustRootClient`.
- `trust_roots:*` is owned by xkms and declared `ScopeCross`
  (`pkg/apimodule/module_scopes.go:142-149`).
- The list is sorted by subject and unpaged: the store holds anchors, not
  issued certificates.

## Schema

`TrustRoot` (`pkg/api/transport/types_trust_roots.go`; proto `TrustRoot`):

| Field | JSON | Meaning |
|---|---|---|
| `Fingerprint` | `fingerprint` | lowercase hex SHA-256 of the DER certificate, 64 characters |
| `Purpose` | `purpose` | `general`, `user-ca`, `bootstrap-ca`, `tpm-manufacturer`, `android-hardware`, `idevid-issuer`, `image-signer`, or `synced` for a quarantined root |
| `Subject`, `Issuer`, `Algorithm` | `subject`, `issuer`, `algorithm` | from the certificate |
| `NotBefore`, `NotAfter`, `AddedAt` | `not_before`, `not_after`, `added_at` | RFC 3339, UTC |
| `Source` | `source` | where the root came from, when known |
| `PEM` | `pem` | the certificate; set by get only |

Requests:

- List: `purpose` (optional) keeps one purpose.
- Get, quarantine, remove: `fingerprint`.
- Import: `pem` (one or more `CERTIFICATE` blocks), `purpose` (optional;
  empty classifies each certificate from its contents), `source` (optional).
  The answer is `{added, skipped}`; a certificate already held is skipped and
  keeps its purpose.

Status codes: list, get, import and quarantine answer `200`; remove answers
`204` (gRPC `TrustRootRemoveResponse`, MCP `{"fingerprint": …}`).

## Errors

| Condition | REST | gRPC | MCP |
|---|---|---|---|
| Tenant-scoped caller; unknown fingerprint | 404 | `NotFound` | not found |
| Malformed fingerprint, purpose, certificate or body | 400 | `InvalidArgument` | invalid params |
| Store not composed or closed | 503 | `Unavailable` | service unavailable |
| Missing permission | 403 | `PermissionDenied` | permission denied |

The table behind it is `apierrors.TrustRootSentinelClasses`; see
[engineering.md](engineering.md#error-semantics).
