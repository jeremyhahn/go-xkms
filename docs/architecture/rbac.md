# Role-Based Access Control (RBAC)

## Overview

go-xkms carries **no RBAC engine of its own**. Roles, permissions, and role
bindings live in the **qrdb identity plane** that xkms hosts in-process as its
datastore. xkms contributes one thing: a single authorization seam that every
transport calls before it dispatches an operation.

The packages that once held a parallel implementation (`pkg/rbac` /
`pkg/keyrbac`, `pkg/authz` / `pkg/keyauthz`, `pkg/policy` / `pkg/keypolicy`)
were deleted in the RBAC unification. Nothing imports them; do not reintroduce
a local role or permission store.

## Architecture

```
request -> authenticator -> auth.WithIdentity(ctx, id)
                                  |
                                  v
                      transport authorization gate
                                  |
                                  v
                  auth.Authorizer.Authorize(ctx, id, resource, action)
                                  |
                                  v
                     qrdbClient.RBAC().Authorize(...)
```

| Piece | Location | Responsibility |
|-------|----------|----------------|
| `auth.Authorizer` | `pkg/auth/authorize.go` | The only authorization seam. Wraps a qrdb `RBACClient`, normalizes an empty tenant to the system tenant, and forwards the decision. |
| Resource / action identifiers | `pkg/auth/permissions.go` | The `Resource*` / `Action*` constants the transports pass in. They mirror qrdb's canonical permission vocabulary; xkms registers none of its own. |
| Wiring | `Server.initializeAuthorization` in `pkg/server/server.go` | Builds `auth.NewAuthorizer(s.qrdbClient.RBAC())` when `auth.enable_rbac` is true and a qrdb client exists. |

`Authorizer.Enabled()` is false for a nil `Authorizer` or one built with a nil
RBAC client; in that state `Authorize` returns nil for everything. That is how
"RBAC disabled" is expressed — there is no permissive local fallback engine.

## Requires the qrdb storage backend

RBAC is backed **exclusively** by the qrdb identity plane, and that plane only
exists when qrdb is the storage backend:

```yaml
storage:
  backend: "qrdb"

auth:
  enabled: true
  type: mtls
  enable_rbac: true
```

With any other backend (`pebble`, `file`, `memory`) there is no qrdb client, so
`initializeAuthorization` leaves the authorizer nil and every transport
authorizes every request — an access control the operator asked for that
silently does nothing. `Config.ComplianceGaps` (`pkg/config/config.go`) reports
that combination and the daemon refuses to start or reload with it. There is
no override flag, environment variable, or build tag.

## Permission model

A permission is a `resource:action` pair, matched by qrdb against the role
grants held by the identity's roles, scoped to the identity's tenant.

Constants declared in `pkg/auth/permissions.go`:

| Resources | Actions |
|-----------|---------|
| `keys`, `certs`, `backends`, `users` | `create`, `get`, `read`, `list`, `update`, `delete`, `sign`, `verify`, `encrypt`, `decrypt`, `rotate`, `import`, `export`, `generate`, `revoke` |

The remaining resources and actions are canonical qrdb permission strings used
verbatim by the transports; `pkg/api/mcp/authz.go` declares them as constants so
two gates cannot disagree on spelling:

| Resource | Actions |
|----------|---------|
| `piv` | `read`, `write`, `delete`, `use` |
| `ssh` | `read`, `write`, `delete` |
| `seal` | `bootstrap`, `initialize_shamir`, `unseal`, `seal`, `status`, `rekey`, `generate_recovery`, `recover_with_keys`, `rotate_root_key`, `enable_encryption` |
| `barrier` | `unseal-share` |
| `ceremony` | `status`, `claim_cert`, `claim_share_complete`, `sign_csr` |
| `credentials` | `submit`, `strategy` |
| `passwords` | `read`, `write`, `delete`, `unlock`, `lock`, `generate` |

Key operations that have no `Action*` constant use `wrap`, `unwrap`, and
`derive` on the `keys` resource.

`pkg/api/mcp/authz.go`'s `methodPermissions` table is the most complete written
record of the vocabulary: it maps every JSON-RPC method to the pair the
equivalent REST / gRPC / QUIC operation already requires, with per-namespace
citations of the transport it was taken from.

## Permission scope

Every permission also declares a **tenancy scope** — how far it reaches across
tenants — and since go-qrdb#504 there is no default: a permission with no
declared scope is refused by the authorizer, and `rbac.ListPermissions` fails
on the first unscoped permission an identity holds, which fails token issuance
rather than a single call. An omission therefore denies login.

| Scope | Reach |
|-------|-------|
| `self` | the identity's own tenant, lifted across all tenants for a system-tenant identity |
| `tenant-only` | the identity's own tenant only, denied to the system tenant — per-tenant custody a platform operator must not hold |
| `cross` | across tenants, reserved for the system tenant |

xkms registers no parallel vocabulary, so go-qrdb declares the scope of nearly
every permission the module contributes. The exceptions — the names go-qrdb
does not declare — are xkms's to own, and they are declared in
`pkg/apimodule/module_scopes.go`:

| Permission | Scope | Why |
|------------|-------|-----|
| `keys:read` | `self` | PKCS#11 object-state and seal-store reads; system-barrier state, and go-qrdb declares the whole `seal:*` family `self` |
| `keys:write` | `self` | the mutating half of the same two stores; strictly less than `keys:delete`/`keys:import`, both `self` |
| `keys:update` | `self` | one compare-and-swap route on the PKCS#11 state store — `keys:write` narrowed |
| `ssh:use` | `self` | the blanket gate on the SSH CA route group, whose siblings `ssh:read`/`write`/`delete` and the matching `piv:use` are all `self` |

Two rules govern that file. **Pin each member, not the family** — a family
helper that later gains a member would scope it silently. **Declare only what
xkms owns** — `RegisterPermissionScope` overwrites and runs after go-qrdb's
package `init()`, so re-declaring a go-qrdb name would replace an upstream
decision with a local one.

`registerRoleGrants` (`pkg/apimodule/module_grants.go`) registers in the order
permissions → scope → role grants, because the authorizer resolves a
permission's scope before it consults the grant.
`pkg/apimodule/module_scopes_test.go` is the build gate: every permission the
module contributes must resolve a scope, through the same SDK path the
authorizer uses.

## Transport enforcement

Every transport authorizes through the same `auth.Authorizer`, so a role grant
means the same thing regardless of how the request arrives.

| Transport | Gate |
|-----------|------|
| REST | `RBACMiddleware.RequirePermission(resource, action)` (`pkg/api/rest/rbac_middleware.go`) applied per route |
| gRPC | `Service.authorize(ctx, resource, action, resourceID)` (`pkg/api/grpc/service.go`) |
| QUIC | Same as REST — QUIC is HTTP/3 served on the unified REST listener, not a separate server package |
| MCP | `Server.authorizeMethod(ctx, method)` (`pkg/api/mcp/authz.go`) before any dispatch path |

Denials, status codes, and the fail-closed behaviour of the MCP gate are
documented in [Authentication configuration](../configuration/auth.md#transport-enforcement).

Authentication is mandatory on every transport whether or not RBAC is enabled.

## Roles

Role definitions and memberships are qrdb records, not xkms constants. The
canonical names — qrdb's FIPS 140-3 six-role model, mirrored by
`cmd/xkmsctl/roles.go` so the strings the CLI sends match what the server
understands:

| Role | Intent |
|------|--------|
| `so` | Security Officer: module initialization and PIN management, separated from key use |
| `admin` | Full access to manage xkms and its users |
| `operator` | Manage keys and certificates, not users |
| `user` | Use keys for cryptographic operations, not manage them |
| `auditor` | View audit logs and key metadata only |
| `custodian` | Participate in key ceremonies and manage key shares |

An authenticated identity carries its qrdb roles in `Identity.Roles`; the
mTLS authenticator populates them from the user record resolved by certificate
SPKI thumbprint (`pkg/auth/qrdb_userstore.go`).

See [Init system roles](../init/roles.md) for how these map onto the PKCS#11
SO/User model and the ceremony flow.

## Managing roles and permissions

Roles, permissions, and user records are reached through the xkms SDK, which
re-exports the qrdb clients so consumers need a single import:

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

ac := xkms.Auth(qrdbClient) // qrdbClient backed by the embedded node

ac.Roles()       // qrdb RoleClient       — role definitions
ac.Permissions() // qrdb PermissionClient — permission registry
ac.RBAC()        // qrdb RBACClient       — Authorize + ListPermissions
ac.Users()       // qrdb UserClient       — user lifecycle
```

There is no local xkms user store. Users are created and bound to an mTLS
client certificate through the same surface:

```go
ac.Users().CreateUser(ctx, ...)
// then bind the cert's SPKI thumbprint so login resolves the user
// via the cert-thumbprint index (xkmsctl admin create --method mtls
// does both in one step).
```

## Best practices

1. **Principle of least privilege** — grant the minimum permissions needed.
2. **Use the six canonical roles** before defining custom ones; separation of
   duties is what makes the SO/operator split meaningful.
3. **Never run production with `enable_rbac: true` on a non-qrdb backend** —
   the daemon refuses it, and there is no override to work around that.
4. **Audit role changes** — role assignment flows through qrdb's HMAC-chained
   audit subsystem.
5. **Review memberships periodically**, especially `admin` and `so`.

## Related Documentation

- [Authentication configuration](../configuration/auth.md) - mTLS, RBAC config, transport enforcement
- [Identity / authorization layering](../auth/layering.md) - the xkms/qrdb boundary
- [Authentication Adapters](adapter-framework.md) - HTTP/gRPC authentication
- [Init system roles](../init/roles.md) - roles in the first-boot ceremony
- [Server Architecture](server-architecture.md) - API server configuration
