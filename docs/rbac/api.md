# RBAC — API

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28

RBAC is cross-cutting, not a capability with its own endpoint set: it is the
authorization gate every other feature's REST route, gRPC RPC, and MCP tool
passes through. This page documents that gate plus the one capability RBAC
does own an API for directly — user lifecycle and role **assignment**. Role
**definition** (custom roles) has no API surface at all; see below.

## How the six transports are shaped

Every transport described in
[`../key-management/api.md`](../key-management/api.md) §"How the six
transports are shaped" carries the RBAC gate. This page assumes that model.

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
  documented under the `acme-issuance` feature folder, not here.

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
| REST / QUIC | `404 Not Found`, body `{"error":"tenant: not found",...}` | tenant routes: `pkg/api/rest/errors.go:130`; `/barrier/enable-encryption`: `pkg/api/rest/handlers_barrier_pin.go:514`; `/ca/sign-csr`: `pkg/api/rest/handlers_ca.go:84` |
| gRPC | `codes.NotFound` | tenant RPCs: `pkg/api/grpc/service_custodian_share_tenant.go:86`; `BarrierEnableEncryption`: `pkg/api/apierrors/tables.go:133` |
| MCP | `JSONRPCCodeNotFound` | tenant methods: `pkg/api/mcp/errors_custodian_tenant.go:57`; `barrier.enableEncryption`: `pkg/api/apierrors/tables.go:133`; `xkms.ca.sign-csr`: `pkg/api/mcp/errors_cert.go:90` |

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
Every denial body/message above is fixed and generic — REST's `"Authentication
required"` / `"Access denied: insufficient permissions"`, gRPC's
`"grpc: authentication required"` / `"grpc: access denied"` (and
`"authentication failed"` from the authentication interceptors, one layer
before `authorize` runs). None of them include the qrdb authorizer's or
authenticator's own error text; that detail is not the caller's to see and
stays server-side (audit event or `slog`) — see engineering.md's Error
semantics and Observability (go-xkms#1103).
