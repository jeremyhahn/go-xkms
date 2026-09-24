# RBAC — API

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-24

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
