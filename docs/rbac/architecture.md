# RBAC — Architecture

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1114, #1115)

## The problem

Every transport xkms serves (REST, gRPC, QUIC, MCP) needs to decide whether
an authenticated caller may perform a given operation. That decision has to
mean the same thing regardless of which transport carried the request, and
it has to compose with multi-tenancy: an identity's reach is scoped to its
own tenant unless it is a system-tenant identity.

## Shape chosen: xkms carries no RBAC engine of its own

Roles, permissions, role grants, and role memberships are **qrdb records**,
living in the identity plane xkms hosts in-process as its datastore (the
`"qrdb"` storage backend — see
[`../storage-engines/architecture.md`](../storage-engines/architecture.md)).
xkms contributes exactly one thing: a single authorization seam
(`auth.Authorizer`) that every transport calls before it dispatches an
operation, plus the resource/action vocabulary its own routes, RPCs, and
tools use.

Packages that once held a parallel implementation — `pkg/rbac` /
`pkg/keyrbac`, `pkg/authz` / `pkg/keyauthz`, `pkg/policy` / `pkg/keypolicy`
— do not exist in this repository (verified absent). Nothing imports them;
do not reintroduce a local role or permission store.

```
request → authenticator → auth.WithIdentity(ctx, id)
                                |
                                v
                    transport authorization gate
              (REST middleware / gRPC helper / MCP dispatch)
                                |
                                v
              auth.Authorizer.Authorize(ctx, id, resource, action)
                                |
                                v
                   qrdbClient.RBAC().Authorize(...)
```

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| `auth.Authorizer` — the only authorization seam | `pkg/auth/authorize.go` | go-xkms |
| Resource / action identifiers | `pkg/auth/permissions.go` — "the ONLY authorization vocabulary in the xkms process" (doc comment) | go-xkms (mirrors qrdb's canonical strings; registers no parallel vocabulary) |
| Role definitions, grants, permission registry, scope declarations | go-qrdb's identity plane (`pkg/permission`, `pkg/role` in go-qrdb) | **go-qrdb** |
| The 5 self-scoped permission exceptions xkms alone owns | `pkg/apimodule/module_scopes.go` | go-xkms |
| Deriving and registering xkms's permission set + granting it to Admin/Owner | `pkg/apimodule/module_grants.go` | go-xkms |
| Wiring (`auth.enable_rbac` → `auth.NewAuthorizer`) | `Server.initializeAuthorization`, `pkg/server/server.go` | go-xkms |
| Per-transport enforcement | `pkg/api/rest/rbac_middleware.go`, `pkg/api/grpc/service.go`, `pkg/api/mcp/authz.go` | go-xkms |
| CLI role-name mirroring for user registration | `cmd/xkmsctl/roles.go` | go-xkms |

## Requires the qrdb storage backend

RBAC is backed **exclusively** by the qrdb identity plane, which only exists
when `storage.backend: "qrdb"`. `Config.ComplianceGaps`
(`pkg/config/config.go`) reports `auth.enable_rbac: true` on any other
backend as a compliance gap, and `cmd/xkmsd` refuses to start or reload on
any reported gap — there is no override flag, environment variable, or
build tag. With any other backend, `initializeAuthorization` leaves the
authorizer `nil` and every transport authorizes every request: an access
control the operator explicitly asked for that would otherwise silently do
nothing.

## Data flow

```
CreateUser(role="operator")
  → roleNameToID: qrdb ListRoles, match by name → role ID
    (unknown name → ErrUnknownRole, refused)
  → qrdb CreateUser with RoleIDs=[id]

request with an identity carrying qrdb roles
  → transport gate calls auth.Authorizer.Authorize(ctx, identity, resource, action)
    → empty tenant normalized to the system tenant
    → qrdbtransport.Identity{Subject, TenantID, Roles, Metadata}
    → qrdbClient.RBAC().Authorize(...) — resolves grants, checks tenancy scope
  → allow (nil) or PermissionDeniedError / ErrUnauthenticated
```

## A self-scope gate does not bound a request's tenant

`Authorizer.Authorize` binds the caller's **own** tenant as the target tenant
(`pkg/auth/authorize.go:61`). A self-scope grant such as `audit:read` or
`keys:get` therefore answers one question: may this identity do this in its own
tenant? It cannot tell whether a tenant ID in the request body names some other
tenant. A tenant Admin holds self-scope `keys:*` and `audit:read`, so any
handler that took a tenant from the request was a cross-tenant hole the gate
could not see.

The rule is to take the tenant from the identity, in the service layer, once
for every transport:

- **Key operations** reject a request `tenant_id` at the transport
  (`tenantForRequest` in `pkg/api/rest/handlers_keyops.go:54` and
  `pkg/api/mcp/handlers.go:1393`). gRPC has no such field.
- **PKCS#11 remote state** accepts a `tenant_id` only when it names the
  caller's own tenant, because the module states its configured tenant
  (`pkcs11StateScope`, `pkg/xkms/servicer_pkcs11state.go:79`). See
  [`../pkcs11-provider-module/architecture.md`](../pkcs11-provider-module/architecture.md).
- **Audit queries** clamp the filter to the caller's tenant. Only a
  system-tenant identity the Authorizer admits for `audit:read:cross` reads
  across tenants (`auditTenantFilter`, `pkg/xkms/servicer_audit.go:119`). That
  is the one place the service consults the Authorizer itself: a `ScopeCross`
  permission is the question "may this identity reach other tenants?", and the
  answer changes what the service does rather than whether the call proceeds.
  See [`../audit-log/api.md`](../audit-log/api.md) §"Tenant scoping".

## Trust boundaries

- **A nil `Authorizer`, or one built with a nil RBAC client, allows
  everything.** That is how "RBAC disabled" is expressed — there is no
  separate permissive engine, just the absence of the real one.
- **Every permission must declare a tenancy scope** (`self` / `tenant-only`
  / `cross`) or the authorizer refuses it outright, and `rbac.ListPermissions`
  — the token-issuance path — fails for any identity holding an unscoped
  permission (go-qrdb#504: there is no implicit default any more). xkms
  declares scope only for the handful of resource:action pairs it alone
  owns; qrdb declares the rest.
- **The cluster control plane is a separate, weaker-gated surface.**
  `xkmsctl cluster`/`rebalance` dial go-qrdb's own control-plane service,
  which is authorized by transport trust (TLS + adaptive auth; Unix socket
  filesystem permissions) rather than this RBAC vocabulary — see
  [`../clustering/architecture.md`](../clustering/architecture.md).
- **The ACME admin surface has its own, separate `roles:*` API** for
  per-tenant ACME role CRUD (`pkg/acme/admin`, `pkg/acme/api/server`). It
  reuses the `auth.ResourceRoles`/`auth.ResourceUsers` constants but is a
  distinct feature (documented under `acme-issuance`), not the xkms-core
  RBAC surface this folder documents, and not reachable through xkms's own
  `/api/v1/users` routes.

## What this feature deliberately does not do

- **It does not implement roles, grants, or a permission registry.** All
  qrdb's.
- **It does not expose role CRUD (create/update/delete a custom role) over
  REST, gRPC, or MCP.** Verified absent — no `/roles` REST route, no role
  RPC on `XKMSService`, no MCP `role.*` tool. The only way to create or edit
  a role is the embedded Go SDK (`xkms.Auth(qrdbClient).Roles()`), which
  returns qrdb's `RoleClient` verbatim. See engineering.md.
- **It does not expose a way to change a user's role after creation.**
  `xkmsctl user update` only enables/disables an account; role assignment
  happens once, at `xkmsctl user register --role`.
