# RBAC — API

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1226, #1227, #1232)

RBAC is cross-cutting, not a capability with its own endpoint set: it is the
authorization gate every other feature's REST route, gRPC RPC, and MCP tool
passes through. This page documents that gate plus the one capability RBAC
does own an API for directly — user lifecycle and role **assignment**. Role
**definition** (custom roles) has no API surface at all; see below.

## How the six transports are shaped

Every transport described in
[`../key-management/api.md`](../key-management/api.md) §"How the six
transports are shaped" carries the RBAC gate. This page assumes that model.

## The same operation requires the same permission on every transport

A capability reachable from more than one transport — for example
`POST /api/v1/keys/wrap` (REST), `WrapKey` (gRPC), and `xkms.wrapKey`
(MCP) — requires the identical `resource:action` pair on all of them. This
is a verified property, not a convention callers must trust: each
transport's own permission table is pinned against its own source
(`internal/authzscan`, engineering.md's Test strategy), and
`pkg/api/authz_consistency_test` additionally cross-checks the three tables
against each other so a permission that drifts on only one transport fails
CI (go-xkms#1232). Two known exceptions are tracked, not silently allowed:
`POST /api/v1/passwords/access-mode` is session-authenticated on REST with
no RBAC permission, where gRPC's `PasswordStoreSetAccessMode` and MCP's
`password.setAccessMode` both require `passwords:write`; and REST's
`/api/v1/pkcs11state/*` routes carry per-verb CRUD actions
(`keys:create`/`get`/`list`/`update`/`delete`) where gRPC's `PKCS11State*`
RPCs collapse to a coarser `keys:write`/`keys:read` tiering. Both are
allowlisted in the consistency golden pending a product decision; see
engineering.md's Invariants.

## User lifecycle — REST

Base path `/api/v1/users` (`pkg/api/rest/routes.go`):

| Method | Path | Permission | Handler |
|---|---|---|---|
| `POST` | `/api/v1/users/` | `users:create` | `handleCreateUser` |
| `GET` | `/api/v1/users/` | `users:list` | `handleListUsers` |
| `GET` | `/api/v1/users/{username}` | `users:read` | `handleGetUser` |
| `GET` | `/api/v1/users/{username}/credentials` | `users:read` | `handleListUserCredentials` |
| `PUT` | `/api/v1/users/{username}` | `users:update` | `handleUpdateUser` (enable/disable only) |
| `POST` | `/api/v1/users/{username}/cert-bindings` | `users:update` | `handleBindUserCert` |
| `DELETE` | `/api/v1/users/{username}` | `users:delete` | `handleDeleteUser` |

`POST /api/v1/users/` body:

```json
{
	"username": "alice",
	"email": "alice@example.com",
	"display_name": "Alice",
	"role": "operator",
	"tenant_id": "",
	"without_email_login_key": false
}
```

`role` must name an existing qrdb role (one of the six `xkmsctl` can assign,
or any custom role created through the SDK) — an unresolvable name fails
the request server-side with the wrapped `*ErrUnknownRole` from
engineering.md, surfaced as a 4xx.

## User lifecycle — gRPC

`pkg/api/grpc/service_user.go`: `CreateUser`, `ListUsers`, `GetUser`,
`DeleteUser`, `EnableUser`, `DisableUser`, `BindUserCert`,
`ListUserCredentials` — the same `users:*` permission per RPC as the REST
table above (`s.authorize(ctx, auth.ResourceUsers, auth.Action*, ...)`).

## User lifecycle — QUIC

Same routes as REST — QUIC is HTTP/3 on the unified REST listener.

## User lifecycle — MCP

`pkg/api/mcp/authz.go` `methodPermissions`:

| Method | Permission |
|---|---|
| `user.create` | `users:create` |
| `user.list` | `users:list` |
| `user.get` | `users:read` |
| `user.delete` | `users:delete` |
| `user.enable` | `users:update` |
| `user.disable` | `users:update` |
| `user.bindCert` | `users:update` |
| `user.listCredentials` | `users:read` |

## What is absent

- **No `/roles` REST route, no role RPC on `XKMSService`, no `role.*` MCP
  tool.** Verified absent across all three. Role CRUD is SDK-only (see
  engineering.md).
- **No role-reassignment endpoint.** `PUT /api/v1/users/{username}` and its
  gRPC/MCP equivalents only flip `enabled`; there is no field or verb that
  changes `RoleIDs` on an existing user.
- **The ACME admin API's `roles:*` routes are a different feature.**
  `pkg/acme/admin/tenant_handlers.go` exposes
  `GET/POST/PUT/DELETE /admin/.../tenants/{id}/roles` gated by
  `roles:{list,create,read,update,delete}` — this is the ACME server's
  per-tenant role CRUD for its own admin surface, not xkms-core RBAC. It is
  documented under the `acme-issuance` feature folder, not here. It binds
  tenants the same way `XKMSService` does below — a foreign tenant, role or
  user answers `404` like a missing one (go-xkms#1225;
  [`../acme-issuance/api.md`](../acme-issuance/api.md#admin-api-tenant-binding-responses)).

## Denial responses

| Transport | No identity | Grant missing / scope rejects |
|---|---|---|
| REST / QUIC | `401 Unauthorized` | `403 Forbidden` |
| gRPC | `codes.Unauthenticated` | `codes.PermissionDenied` (via qrdb's authorizer) |
| MCP | fails closed at server construction if RBAC is enabled with no usable authorizer; per-call denial follows the same allow/deny decision as the other transports | |

## Tenant binding responses

Passing the RBAC gate is not enough to act on a tenant named in the request.
`XKMSService` binds that tenant to the caller
(`pkg/xkms/tenant_binding.go:67`), and a tenant-scoped caller naming another
tenant gets **the same answer a nonexistent tenant gets**, not a denial:

| Transport | Answer | Mapping site |
|---|---|---|
| REST / QUIC | `404 Not Found`, body `{"error":"tenant: not found",...}` | tenant routes: `pkg/api/rest/errors.go:130`; `/barrier/enable-encryption`: `pkg/api/rest/handlers_barrier_pin.go:504`; `/ca/sign-csr`: `pkg/api/rest/handlers_ca.go:84` |
| gRPC | `codes.NotFound` | tenant RPCs: `pkg/api/grpc/service_custodian_share_tenant.go:86`; `BarrierEnableEncryption`: `pkg/api/apierrors/tables.go:147` |
| MCP | `JSONRPCCodeNotFound` | tenant methods: `pkg/api/mcp/errors_custodian_tenant.go:57`; `barrier.enableEncryption`: `pkg/api/apierrors/tables.go:147`; `xkms.ca.sign-csr`: `pkg/api/mcp/errors_cert.go:90` |

Affected capabilities: get, delete, barrier init / unseal / status of a
tenant; `ListTenants` returns only the caller's own tenant; enable-encryption
on another tenant's barrier or on the system barrier; a CSR whose SPIFFE
tenant names another tenant.

**Plan changes** (`PUT /api/v1/tenants/{tenantID}/entitlements` and
`/quotas`, gRPC `UpdateTenantEntitlements` / `UpdateTenantQuotas`, MCP
`xkms.updateTenantEntitlements` / `xkms.updateTenantQuotas`) require
`tenants:set_entitlements` / `tenants:set_quotas` at the gate — a caller
without the grant gets `403` / `PermissionDenied` — and are then refused with
the not-found answer above to **every** tenant-scoped caller, including one
naming its own tenant. Only a platform (system-tenant) identity changes a
plan.

**Platform-global operations** (go-xkms#1226, #1227) are refused with the
same not-found answer to every tenant-scoped caller, whatever grants it
holds; only a platform (system-tenant) identity, or an in-process caller with
no identity, reaches them:

| Capability | REST | gRPC / Unix | MCP |
|---|---|---|---|
| sealed platform store | `/api/v1/platform/secrets[/{name}[/reseal]]`, `/api/v1/platform/status` | `SealStore*` | `sealStore.*` |
| credentials | `POST /api/v1/credentials/submit`, `GET /api/v1/credentials/` | no RPC | `credentials.submit` |
| system barrier | `/api/v1/barrier/*` except `enable-encryption` | `Barrier*` except `BarrierEnableEncryption` | `barrier.*` except `barrier.enableEncryption` |
| token PINs | `/api/v1/pin/*` | `SetSOPIN` … `ResetLockout` | `xkms.setSOPIN` … `xkms.resetLockout` |
| server PIV card | `/api/v1/piv/slots*` | `*PIV*` | `xkms.*PIV*` |
| tenant TPM modes and vTPMs | `/api/v1/tenants/{tenantID}/tpm*` | `*TenantTPMMode`, `TenantVTPM*` | `xkms.*TenantTPMMode`, `xkms.tenantVTPM*` |

The refusal is raised in the service (`pkg/xkms/tenant_binding.go:88`) and
mapped by: REST `pkg/api/rest/seal_store_handlers.go:268`,
`policy_handlers.go:367`, `handlers_credentials.go:90`,
`handlers_barrier_pin.go:504` (barrier), `:564` (PIN), and `errors.go:162`
(PIV, through `handleError`); gRPC and MCP through the shared tables
`pkg/api/apierrors/tables.go:39` (seal store), `:71` (PIV), `:96` (PIN),
`:147` (barrier), `:192` (policy), plus MCP's credential table
`pkg/api/mcp/handlers_init_credentials.go:124`. `barrier.enableEncryption`
keeps its tenant binding: a tenant may still migrate its own barrier.

## Internal error responses

A denial is not the only response that must not explain itself. Every
transport separates **client-facing** errors, whose text is written for the
caller, from **internal** ones, whose text is withheld and logged server-side
with the request's context (go-xkms#1118; the gRPC authorization path was
fixed the same way by go-xkms#1103). Status codes are never changed by the
scrub; only the text is.

| Transport | Client-facing (text kept) | Internal (text withheld) | Where it is decided |
|---|---|---|---|
| REST | every 4xx, plus `501` (capability boundary) and `503` (unconfigured subsystem, sealed barrier) | `500` and every other 5xx: the body's `error` is `internal server error` | `clientErrorText`, `pkg/api/rest/errors.go:141`, called by `writeError`/`writeErrorWithMessage` (`errors.go:94`, `errors.go:101`); status rule `isInternalStatus`, `errors.go:126` |
| MCP (unified server tools) | every classified `*KeyOpError`: InvalidParams, NotFound, Forbidden, ServiceUnavailable, MethodNotFound, and classified conditions JSON-RPC can only put on the Internal code (sealed barrier, PIN lockout, quota) | an unclassified `*KeyOpError` on the Internal code, or any error nobody classified: the message is `xkms: internal error` | `ClientError`, `pkg/api/mcp/errors_keyops.go:76`, rendered by `pkg/apimodule/module_mcp.go:121`; classification flag `KeyOpError.Classified`, `errors_keyops.go:47` |
| ACME admin JSON-RPC | Not found / Unauthorized results keep their text in `error.data` | an internal fault, and any authorization denial, carries no `data` | `handleMCP`, `pkg/acme/api/server/server.go:1118`, `server.go:1141` |

The withheld error is logged, never dropped:

- **REST** logs `rest: internal error withheld from client` with `method`,
  `path`, `status`, `request_id` (the correlation ID) and the full `error`
  (`logWithheldError`, `pkg/api/rest/middleware_errorlog.go:77`). The request
  reaches the error path through the ResponseWriter that
  `errorLogMiddleware` (`middleware_errorlog.go:47`) installs on both mounts:
  the legacy router (`pkg/api/rest/server.go:652`) and the unified API
  server's `BindRoute` (`pkg/api/rest/module_support.go:61`). Because the
  scrub lives in the one writer every handler calls, a handler's direct
  `writeError(w, err, http.StatusInternalServerError)` is scrubbed without a
  per-site change. The two writers that do not go through `writeError` use
  the same function: the SSH envelope (`pkg/api/rest/handlers_ssh.go:576`) and
  the PKCS#11 state handlers (`pkg/api/rest/pkcs11state_handlers.go:69`).
- **MCP** logs `mcp: internal error withheld from client` with `method`,
  `tool`, `request_id` and the full `error`, once, in `InvokeMethod`
  (`pkg/api/mcp/module_support.go:114`, `module_support.go:152`), the single
  entry every tool, tenant gate and authorization gate failure passes
  through.
- **ACME admin JSON-RPC** logs the denial reason or the internal fault with
  `method`, `path` and `request_id` (`logMCPError`,
  `pkg/acme/api/server/server.go:1155`).

`tenantgate.ErrTenantNotFound`'s text names only the caller's own tenant; the
registry lookup failure it wraps stays reachable through `Unwrap` for logs and
`errors.Is`, never in the message (`pkg/api/tenantgate/tenantgate.go:68`).

Every denial body/message above is fixed and generic — REST's `"Authentication
required"` / `"Access denied: insufficient permissions"`, gRPC's
`"grpc: authentication required"` / `"grpc: access denied"` (and
`"authentication failed"` from the authentication interceptors, one layer
before `authorize` runs). None of them include the qrdb authorizer's or
authenticator's own error text; that detail is not the caller's to see and
stays server-side (audit event or `slog`) — see engineering.md's Error
semantics and Observability (go-xkms#1103).
