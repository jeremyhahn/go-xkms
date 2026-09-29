# RBAC — Architecture

<<<<<<< HEAD
> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1114, #1115, #1230)
=======
> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1114, #1115, #1231)
>>>>>>> origin/security/1231-frost-tenant

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
| `auth.HoldsSystemRole` — the only role-membership check, for the one decision that is membership rather than a permission | `pkg/auth/rolemembership.go:71` | go-xkms (resolves through qrdb's `ResolveSystemRoleID`) |
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
- **Key lookups and listings** resolve inside the caller's tenant in the
  service, on every transport. Another tenant's key is `ErrKeyNotFound`, the
  same answer a missing key gets, so a `keys:*` grant never reaches past the
  holder's tenant (go-xkms#1218; see
  [`../key-management/engineering.md`](../key-management/engineering.md)
  §"Key lifecycle RPCs resolve inside the caller's tenant").
- **FROST threshold keys** are stored per tenant and resolved inside the
  caller's tenant for every route that names one — get, delete, Round 1 and
  Round 2 signing, aggregate, verify — and a FROST listing holds only the
  caller's keys (`frostKeyAttrs` and `FrostListKeys`,
  `pkg/xkms/servicer_frost.go:207` and `:406`; go-xkms#1231). The FROST
  routes carry the ordinary `keys:*` permissions
  (`pkg/api/rest/routes.go:174-182`), so without this a tenant Admin's
  `keys:sign` reached every tenant's key shares. See
  [`../frost-threshold-signing/architecture.md`](../frost-threshold-signing/architecture.md)
  §"Tenancy".
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
- **SSH keys, host pins and authorized_keys entries** are addressed by
  `(scope, owner, name)`, where the owner is a tenant ID or a subject. The SSH
  service every transport calls binds the owner to the caller
  (`pkg/ssh/tenancy/client.go:170-182`) and serves each tenant from its own
  storage partition and backend-key namespace, so equal subjects in two
  tenants never meet. Another owner's asset answers as a missing one; a
  write under it creates nothing (go-xkms#1230; see
  [`../ssh-keys/architecture.md`](../ssh-keys/architecture.md) §"Owner
  binding and tenant partitions"). REST's SSH routes also gate per verb now
  — `ssh:read`/`ssh:write`/`ssh:delete`, `ssh:use` to sign
  (`pkg/api/rest/routes.go:476-503`) — instead of one blanket `ssh:use`.
## Identities carry role identifiers, never role names

Every authenticated identity carries qrdb role **identifiers** in `Roles`:
go-qrdb's middleware sets `Identity.Roles = user.RoleIDs`, and xkms's mTLS
authenticator copies the same slice (go-xkms#1069). A role *name* such as
`"admin"` or `"so"` therefore never appears on a store-resolved identity. It
appears only where an authenticator copied an unverified claim — an OIDC or
JWT `roles`/`groups` claim for a subject with no qrdb user record.

So no authorization decision compares `Roles` against a role name. Three
places once did (go-xkms#1074), each with a different effect:

| Former check | What it gated | Store-resolved identity | Name-bearing identity |
|---|---|---|---|
| `pkg/xkms/servicer_password.go` shared-password override (`admin`, `so`) | a non-owner updating or deleting a shared vault entry | never matched: tenant Admin and SO were refused (fail-closed) | matched: override granted (fail-open) wherever the transport admitted the caller — in practice, deployments with RBAC disabled |
| `pkg/xkms/servicer_ca.go` `SignCSR` (`admin`, `user`, `operator`) | CSR signing over REST and MCP, after the transport's `certs:generate` | never matched: every authenticated caller was refused (fail-closed) | only restrictive, so never granted anything |
| `pkg/api/tenantgate/tenantgate.go` Security Officer exemption (`so`) | skipping the tenant-registered and tenant-sealed gate on REST, gRPC and MCP | never matched | matched: the gate was skipped (fail-open); RBAC still applied afterwards |

Each was replaced by the model the operation already declared:

- **CSR signing** is a `certs:generate` operation, enforced by every
  transport before dispatch (`pkg/api/rest/routes.go:237`,
  `pkg/api/mcp/authz.go:170`, `pkg/api/grpc/service_ca.go:136`). The
  servicer no longer makes a second decision (`pkg/xkms/servicer_ca.go:139`).
- **The shared-password override** is genuinely role membership: Admin and
  Operator hold the same `passwords:*` grants, so no permission separates
  the vault administrator from any other writer. It resolves membership with
  `auth.HoldsSystemRole` against the identity's own tenant
  (`pkg/xkms/servicer_password.go:113`, `:144`).
- **The tenant gate** has no role exemption. Cross-tenant scope is qrdb's
  system-tenant rule alone, through `auth.IsCrossTenant`
  (`pkg/api/tenantgate/tenantgate.go:107`). The system tenant's Security
  Officer is cross-tenant already; a tenant-local officer is confined to its
  tenant, as qrdb's authorizer confines it.

`Identity.HasRole` belongs to go-qrdb and cannot be removed here. The
`forbidigo` rule in `.golangci.yml:115` fails the build on any call to it.

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
