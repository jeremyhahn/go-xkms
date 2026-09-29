# RBAC — Engineering Contract

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1114, #1115)

## Exported surface

### `pkg/auth/authorize.go`

```go
type Authorizer struct{ /* unexported */ }

func NewAuthorizer(rbac qrdbtransport.RBACClient) *Authorizer
func (a *Authorizer) Enabled() bool
func (a *Authorizer) Authorize(ctx context.Context, identity *Identity, resource, action string) error
```

`Enabled()` is `false` for a nil `*Authorizer` or one built with a nil RBAC
client. `Authorize` returns `nil` (allowed) whenever `!Enabled()`;
`ErrUnauthenticated` when `identity == nil`; otherwise delegates to
`rbac.Authorize` after normalizing an empty `identity.TenantID` to
`qrdbsdk.SystemTenantID`.

`Authorize` binds the **caller's own tenant** as the request's target tenant
(`pkg/auth/authorize.go:61`). It therefore cannot tell whether a tenant ID
*named in the request* belongs to the caller: a Tenant Admin holding the
self-scoped `tenants:*` / `tenant_barrier:*` grants passes the gate for a
request naming any tenant. Confining that is the job of the service-layer
tenant binding below, not of the transports.

### `pkg/xkms/tenant_binding.go` — the tenant binding

```go
type TenantBindingError struct {
	Op             string
	CallerTenantID string
	TargetTenantID string // "" is the system scope
}
func (e *TenantBindingError) Error() string // qrdbsdk.ErrTenantMissing's message, verbatim
func (e *TenantBindingError) Unwrap() error // qrdbsdk.ErrTenantMissing
```

`bindTenantTarget(ctx, op, target)` (`pkg/xkms/tenant_binding.go:67`) admits
a cross-tenant identity (`auth.IsCrossTenant`: no identity, an empty tenant,
or the reserved system tenant) for any target, and a tenant-scoped identity
only when `target` is its own tenant; an empty target is the system scope and
is refused to a tenant-scoped caller. `requirePlatformScope(ctx, op, target)`
(`:80`) admits only a cross-tenant identity. Both refuse with a
`*TenantBindingError` (`:34`), which is exactly what the composed go-qrdb
TenantService returns for an unknown tenant: same sentinel, same message
(`:46`, `:52`). Every transport already answers that sentinel with its
not-found status, so a foreign tenant ID is indistinguishable from an unused
one. The fields exist for server-side diagnostics (`errors.As`) and are never
rendered.

The binding is applied once, in `XKMSService`, and no transport repeats it:

| Method | Check | Site |
|---|---|---|
| `GetTenant` | `bindTenantTarget` | `pkg/xkms/servicer_tenant.go:94` |
| `ListTenants` | filters to the caller's tenant (`visibleToCaller`) | `pkg/xkms/servicer_tenant.go:127` |
| `DeleteTenant` | `bindTenantTarget` | `pkg/xkms/servicer_tenant.go:144` |
| `TenantBarrierInit` | `bindTenantTarget` | `pkg/xkms/servicer_tenant.go:191` |
| `TenantBarrierUnseal` | `bindTenantTarget` | `pkg/xkms/servicer_tenant.go:246` |
| `TenantBarrierStatus` | `bindTenantTarget` | `pkg/xkms/servicer_tenant.go:283` |
| `UpdateTenantEntitlements` | `requirePlatformScope` | `pkg/xkms/servicer_tenant.go:313` |
| `UpdateTenantQuotas` | `requirePlatformScope` | `pkg/xkms/servicer_tenant.go:340` |
| `BarrierEnableEncryption` | `bindTenantTarget` (empty `TenantID` = system barrier) | `pkg/xkms/servicer_barrier.go:310` |
| `SignCSR` | `bindTenantTarget` when `TenantID` is set (the SPIFFE tenant SAN) | `pkg/xkms/servicer_ca.go:178` |
### `pkg/auth/rolemembership.go` — role membership

var ErrRoleClientRequired error

type RoleResolutionError struct {
	TenantID string
	Role     string
	Err      error

func HoldsSystemRole(ctx context.Context, roles qrdbtransport.RoleClient, identity *Identity, roleName string) (bool, error)

`HoldsSystemRole` (`pkg/auth/rolemembership.go:71`) reports whether the
identity holds the named qrdb system role of **its own** tenant. It resolves
the name to the identifier the role is persisted under with
`qrdbsdk.ResolveSystemRoleID` over the node's role store (`:88`). Then it
matches that identifier against `identity.Roles`. A role name on the
identity matches nothing. An empty `TenantID` resolves in the system tenant.

A nil or roleless identity is not a member. A nil role client returns
`ErrRoleClientRequired` (`:29`). A store failure, including a store that
returns neither a role nor an error, returns `*RoleResolutionError` (`:35`).
Both mean membership is unknown, and the caller must fail closed.

Use it only where the decision is role membership. The one such call site is
the shared-password administrator override,
`XKMSService.checkSharedPasswordOwnership`
(`pkg/xkms/servicer_password.go:128`). It admits the owner, or a member of
`sharedPasswordAdministratorRoles` (Admin, SO; `:113`), and refuses everyone
else with `staticpw.ErrNotOwner`, including every caller when no role
client is wired. Every other decision is a resource:action through
`Authorizer`.

### `pkg/auth/permissions.go` — the vocabulary

The full resource and action list, verbatim from the constants (this file is
"the ONLY authorization vocabulary in the xkms process" — doc comment):

**Resources:** `keys`, `certs`, `backends`, `users`, `roles`, `tenants`,
`audit`, `admin`, `seal`, `barrier`, `piv`, `ssh`, `passwords`, `pin`,
`tenant_barrier`, `ceremony`, `credentials`, `bootstrap`, `acme_accounts`,
`acme_orders`, `acme_eab`, `ca`.

**Actions:** `sign`, `verify`, `encrypt`, `decrypt`, `create`, `rotate`,
`delete`, `list`, `get`, `import`, `export`, `wrap`, `unwrap`, `derive`,
`generate`, `revoke`, `read`, `read:cross`, `update`, `set_entitlements`, `set_quotas`,
`write`, `use`, `disable`, `status`,
`capabilities`, `bootstrap`, `seal`, `unseal`, `rekey`, `rotate_root_key`,
`generate_recovery`, `recover_with_keys`, `initialize_shamir`,
`unseal-share`, `enable_encryption`, `init`, `claim_cert`,
`claim_share_begin`, `claim_share_complete`, `sign_csr`,
`enroll_custodian`, `revoke_custodian`, `submit`, `strategy`, `lock`,
`unlock`.

`read:cross` (`auth.ActionReadCross`, `pkg/auth/permissions.go:148`) is used
only as `audit:read:cross`, qrdb's `AuditReadCross`. The qrdb SDK does not
re-export that constant, so xkms restates the string.
`TestActionReadCross_MatchesQRDBAuditReadCross` (`pkg/auth/permissions_test.go`)
fails the build if qrdb's registry stops knowing it. qrdb declares it
`ScopeCross`. Admin holds it and Auditor does not.

### `pkg/xkms` — the service's Authorizer

```go
func (s *XKMSService) SetAuthorizer(a *auth.Authorizer)
```

(`pkg/xkms/service.go:324`.) The server passes it the transports' own
Authorizer (`pkg/server/server.go:835`). The service uses it for one decision
the route gate cannot make: whether a system-tenant caller of `QueryAudit`
holds `audit:read:cross`. A nil Authorizer is RBAC-disabled, as everywhere
else. The service clamps tenant identities whatever the Authorizer says.

A permission is a `resource:action` pair. A transport must never declare its
own resource or action string literal — `internal/authzscan` enforces this
for the per-call-site transports (gRPC, QUIC) by parsing their source and
rejecting a raw string literal or an unknown constant name (see Test
strategy).

### `cmd/xkmsctl/roles.go` — CLI role names

```go
type Role string
const (
	RoleSO        Role = "so"
	RoleAdmin     Role = "admin"
	RoleOperator  Role = "operator"
	RoleUser      Role = "user"
	RoleAuditor   Role = "auditor"
	RoleCustodian Role = "custodian"
)
func IsValidRole(r Role) bool
```

These mirror **six** of go-qrdb's seven built-in roles (verified against
the vendored `go-qrdb@v0.19.0-alpha` dependency, `pkg/permission/builtin_role_grants.go`):
SO, Admin, Operator, User, Auditor are derived from a shared registry;
Custodian holds a fixed, minimal Shamir/barrier share-submission set; Owner
is the standard-posture superuser (`permission.All()`). **`xkmsctl` cannot
assign `"owner"`** — `IsValidRole` rejects it; only the six roles above are
CLI-assignable.

`userRegisterCmd`'s `--role` flag help text (`cmd/xkmsctl/user.go`) lists
exactly these six roles; any other value fails at runtime with
`ErrInvalidRole`.

### `pkg/apimodule/module_scopes.go` — the permissions xkms alone scopes

Since go-qrdb#504 removed the implicit default, every permission must
declare a tenancy scope (`self` / `tenant-only` / `cross`) or the authorizer
refuses it. qrdb declares the scope of its own canonical vocabulary; xkms
declares scope **only** for the resource:action pairs it alone owns —
verified as exactly five, all `ScopeSelf`:

```go
func selfScopedPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		"keys:read",    // PKCS#11 object-state + seal-store reads (system-barrier state)
		"keys:write",   // the mutating half of the same two stores
		"keys:update",  // one compare-and-swap route on the PKCS#11 state store
		"ssh:use",      // blanket gate on the SSH CA route group
		"bootstrap:read", // the trust-bootstrap listener's own public keys (go-xkms#632)
	}
}
```

An in-code comment above this function states "the four below are the
exceptions" — that count is **stale**; the function returns five. This
document reflects the code, not the comment.

### `pkg/apimodule/module_grants.go` — what xkms grants, and to whom

```go
func registerRoleGrants()      // runs once, before the embedded node seeds roles
func modulePermissions() []qrdbsdk.Permission
```

`modulePermissions` derives the full set of resource:action pairs xkms
declares, from **three** surfaces: the REST route table (`xkmsrest.Routes()`),
the MCP method specs (`xkmsmcp.ModuleMethods()`), and the
`qrdb.v1.permission` proto option on the `xkmsv1` gRPC service descriptors —
so a new RPC/route/tool is granted the moment it is declared, with no
hand-maintained list to fall out of sync.

`registerRoleGrants` then, in this fixed order (permission → scope → grant,
because the authorizer resolves scope before consulting a grant):

1. Registers every derived permission into qrdb's global registry.
2. Declares the tenancy scope of the five xkms-owned exceptions above.
3. Grants the **entire** derived permission set to exactly **two** built-in
   roles: `Admin` and `Owner`.

**The Security Officer role receives none of it** — the doc comment states
why explicitly: "xkms's surface is overwhelmingly cryptographic and qrdb's
SoD invariant (FIPS 140-3 AS10.03) forbids crypto grants to SO." Operator,
User, Auditor, and Custodian are **not** bulk-granted xkms's permission set
either; those roles hold only whatever go-qrdb's own built-in role
definitions already assign for the permission *names* xkms happens to share
with qrdb's canonical vocabulary (e.g. `keys:sign`, `certs:generate`). For
the xkms-exclusive families — `ssh:*`, `piv:*`, `passwords:*`, `seal:*`,
`barrier:*`, `ceremony:*`, `credentials:*`, `bootstrap:read`,
`tenant_barrier:*` — a role other than Admin or Owner has whatever qrdb's
registry independently decided for that exact name, which this document
does not enumerate permission-by-permission; verify against
`pkg/permission/builtin_role_grants.go` in the go-qrdb dependency for a
specific permission before assuming a non-Admin role holds it.

## Invariants

- **xkms registers no parallel resource/action vocabulary.** Every constant
  in `pkg/auth/permissions.go` mirrors a name qrdb's canonical registry
  already uses, or (for the handful xkms alone owns) is registered into that
  same registry — never checked against a separate local table.
- **Scope declaration order matters and is enforced in code.** Permissions,
  then scopes, then grants — reversing it breaks token issuance for any
  identity holding a not-yet-scoped permission.
- **`RegisterPermissionScope` overwrites and runs after qrdb's own
  `init()`.** Re-declaring a name qrdb already scopes would silently
  override an upstream decision; `pkg/apimodule/module_scopes_test.go`
  (`TestModuleDeclaresOnlyItsOwnScopes`) is the build gate against that.
- **A route/RPC/tool's resource and action must be `pkg/auth` constants,
  never string literals**, on the two transports without an in-process
  table to check against (gRPC, QUIC) — enforced by `internal/authzscan`.
- **A tenant named in a request is never the target tenant.** The gate
  resolves a self-scope permission against the caller's own tenant, so a
  handler that forwards a request tenant to a store or query escapes it. The
  service derives the tenant from the identity, as `pkcs11StateScope` and
  `auditTenantFilter` do. A transport must not do this itself, and must not
  forward a request tenant unexamined.
- **The mTLS authenticator enforces qrdb's permitted-method policy.** A
  certificate that resolves to an active account is refused when the
  account's `AuthMethods` (qrdb `User.AuthMethods`) is non-empty and does not
  name `mtls` (`qrdbsdk.MethodMTLS`). `QRDBUserStore` projects the policy onto
  `MTLSUser.AuthMethods` (`pkg/auth/qrdb_userstore.go:69`);
  `MTLSAuthenticator.userIdentity` checks it after the enabled check
  (`pkg/auth/mtls.go:247`) via `checkAuthMethod`
  (`pkg/auth/authmethod.go:34`), which applies go-qrdb's
  `auth/middleware` `checkAuthMethod` contract unchanged: an **empty policy
  states no restriction**, the method name is normalized with
  `qrdbsdk.NormalizeAuthMethods` and compared against the stored entries,
  and a name that does not survive normalization is refused. A refused
  account is never admitted through the certificate-field fallback that
  serves certificates when no `UserStore` is configured — a `UserStore`
  configuration never falls back to certificate fields at all, whether the
  refusal is disablement, policy exclusion, or an unbound certificate.
- **A tenant ID taken from a request is bound in `XKMSService`, never in a
  transport.** The RBAC gate cannot do it (see `Authorize` above); a
  transport-level copy is a second owner that drifts. A new service method
  that targets a caller-supplied tenant calls `bindTenantTarget` (or
  `requirePlatformScope`) and gets a row in the table above.
- **Plan management is platform-only.** Entitlements and quotas are gated on
  qrdb's dedicated `tenants:set_entitlements` / `tenants:set_quotas`
  (`pkg/auth/permissions.go:154-155`), never `tenants:update`, on every
  transport: `pkg/api/rest/routes.go:293-294`, `pkg/api/mcp/authz.go:239-240`,
  `pkg/api/grpc/service_custodian_share_tenant.go:896,922`, and the
  `qrdb.v1.permission` options at `pkg/api/grpc/proto/xkmsv1/xkms.proto:647,654`.
  Because both permissions are self-scoped in qrdb and qrdb's built-in Admin
  role grants `tenants:set_entitlements`, the RBAC gate alone would still
  let a Tenant Admin change its own plan; `requirePlatformScope` is what
  refuses it.
- **No authorization decision compares `Identity.Roles` against a role
  name.** Identities carry role identifiers, so a name comparison never
  matches a real grant and does match an unverified token claim
  (go-xkms#1074). `Identity.HasRole` is go-qrdb's and does exactly that, so
  the `forbidigo` rule at `.golangci.yml:115` forbids calling it anywhere in
  the module. Role membership goes through `HoldsSystemRole`.
- **Servicers do not authorize.** The permission is enforced once, at the
  transport, before dispatch. `XKMSService.SignCSR` used to run its own
  role check on top of `certs:generate`; it no longer does
  (`pkg/xkms/servicer_ca.go:139`).
- **No role is exempt from tenant scoping.** `tenantgate.Access` consults
  only `auth.IsCrossTenant`, qrdb's system-tenant rule
  (`pkg/api/tenantgate/tenantgate.go:107`).
- **Role reassignment after user creation does not exist.** `roleNameToID`
  runs once, at `CreateUser`; there is no update path.
- **With a `UserStore` configured, an mTLS identity is always a bound,
  enabled, permitted user's.** `MTLSAuthenticator.userIdentity`
  (`pkg/auth/mtls.go:226`) builds the identity only from a user record that
  is bound, enabled, and whose permitted-method policy allows `mtls`. An
  unbound certificate (qrdb's typed `UserNotFoundError`) is refused with
  `ErrCertNotBound` (`pkg/auth/mtls.go:234-236`). Any other store error
  (sealed tenant barrier, failed index read, unreachable remote) fails
  closed as `*UserLookupError` (`pkg/auth/mtls.go:238`). None of these falls
  back to the certificate's fields. That identity would carry the
  caller-chosen CN as `Subject` and first OU as `TenantID`. Handlers scope
  per-user state on that pair (the password vault,
  `pkg/api/rest/password_handlers.go:95`), and with RBAC disabled nothing
  else stands between it and the handler. During an outage it would also
  admit an account the store would have refused. Only an authenticator built
  without a store (`pkg/auth/mtls.go:275`, used when no qrdb identity plane
  is hosted) derives an identity from certificate fields.

- **The OIDC authenticator bounds what it reads from the identity
  provider.** The discovery document, the JWKS and the userinfo response are
  each read through `readOIDCResponse` (`pkg/auth/oidc.go:50`), which
  refuses a body over 1 MiB (`maxOIDCResponseBytes`, `oidc.go:46`) with
  `ErrOIDCResponseTooLarge` (`oidc.go:94`) instead of buffering it.

## Error semantics

| Error | Where | Meaning |
|---|---|---|
| `ErrUnauthenticated` | `pkg/auth/errors.go` | `Authorize` called with a nil identity while enabled |
| `*AuthMethodNotPermittedError{Username, TenantID, Method, Permitted}` | `pkg/auth/errors.go:58` | the certificate resolved to an active account whose permitted-method policy excludes `mtls`; mirrors qrdb's `auth/middleware` error of the same name |
| `ErrCertNotBound` | `pkg/auth/errors.go:48` | mTLS authenticator with a `UserStore`: the client certificate's SPKI thumbprint is bound to no user. The request is unauthenticated (REST 401), and the gate never runs |
| `*UserLookupError{Err}` | `pkg/auth/errors.go:85` | mTLS authenticator with a `UserStore`: the store failed for any reason other than a definite not-found. It fails closed, and `Err` carries the store's error |
| `*xkms.TenantBindingError` | `pkg/xkms/tenant_binding.go:34` | a tenant-scoped caller named another tenant (or the system scope), or asked for a plan change; unwraps to `qrdbsdk.ErrTenantMissing` and renders as not-found on every transport |
| qrdb's `PermissionDeniedError` | returned by `rbac.Authorize` | grant missing, or tenant scope gate rejects the request |
| `ErrAuthorizerRequired` | `pkg/api/rest/errors.go` | `rest.NewServer` refuses to construct when `EnableRBAC` is true but no usable authorizer was supplied — fails closed at construction, never falls back to allow-all |
| `*ErrUnknownRole{Role}` | `pkg/xkms/errors.go` | `CreateUser`'s role name does not match any existing qrdb role, wrapped in `*ErrUserOperation{Operation: "resolve role"}` |
| `ErrInvalidRole` | `cmd/xkmsctl` | `--role` value fails `IsValidRole` |
| `ErrRoleClientRequired` | `pkg/auth/rolemembership.go:29` | `HoldsSystemRole` called without a role client: membership unknown, fail closed |
| `*RoleResolutionError{TenantID, Role, Err}` | `pkg/auth/rolemembership.go:35` | the role store could not resolve the system role's identifier; surfaces from `PasswordUpdate` / `PasswordDelete` on a non-owner's shared entry |

**The client never sees the error text above verbatim** (go-xkms#1103). Every
transport's gate translates a denial into a fixed, generic message —
`ErrAccessDenied`/`ErrAuthenticationRequired` on gRPC
(`pkg/api/grpc/service.go`), `"Access denied: insufficient permissions"`/
`"Authentication required"` on REST (`pkg/api/rest/rbac_middleware.go`) — and
records the real cause server-side instead: gRPC's `Service.authorize` in the
audit event's `Details["reason"]` (see Observability), REST's
`RBACMiddleware` via `slog.Warn`. `pkg/api/grpc/server.go`'s authentication
interceptors follow the same split one level up the stack, before an
identity even reaches `authorize`: a rejected credential (a user-store or
barrier failure, or why a certificate was refused) becomes the fixed
`errAuthenticationFailed` ("authentication failed") on the wire, logged via
`s.logger.Warn` server-side.

MCP fails closed the same way REST does: `mcp.NewServer` refuses to start
serving when RBAC is enabled without a usable authorizer, rather than
silently running with RBAC believed-enabled-but-not-enforced (comment,
`pkg/server/server.go`).

## Configuration

```go
type AuthConfig struct {
	Enabled    bool `yaml:"enabled"`
	Type       string `yaml:"type"` // noop, mtls, jwt, adaptive, composite
	EnableRBAC bool `yaml:"enable_rbac"`
	// ...
}
```

`auth.enable_rbac` defaults to `false` (no default set in `Defaults()`).
Environment variable: `XKMS_AUTH_ENABLE_RBAC` (the general `XKMS_<PATH>`
rule). RBAC requires `storage.backend: "qrdb"` — see architecture.md and
[`../storage-engines/engineering.md`](../storage-engines/engineering.md).

```yaml
storage:
  backend: "qrdb"
auth:
  enabled: true
  type: mtls
  enable_rbac: true
```

`Server.initializeAuthorization` (`pkg/server/server.go`):

```go
if s.config.Auth.EnableRBAC && s.qrdbClient != nil {
	s.rbacAuthorizer = auth.NewAuthorizer(s.qrdbClient.RBAC())
} else {
	s.rbacAuthorizer = nil // "RBAC enabled but no qrdb identity plane" warns; otherwise "disabled (allow all)"
}
```

This warning path is reachable only by an embedded or test caller that
constructs `pkg/server` directly with a non-`qrdb` backend and
`enable_rbac: true` — `cmd/xkmsd` never reaches it, because
`Config.ComplianceGaps` refuses that combination before startup.

## Transport enforcement

| Transport | Gate | Notes |
|---|---|---|
| REST | `RBACMiddleware.RequirePermission(resource, action)` (`pkg/api/rest/rbac_middleware.go`), applied per `RouteSpec` in `pkg/api/rest/routes.go` where `Auth == RouteAuthPermission`, ahead of the route's body bound (`pkg/api/rest/server.go:724`), so a denied caller gets 403 before its body is read | table-driven; a route's `Enabled` guard can also remove it entirely when its subsystem is unconfigured |
| gRPC | `Service.authorize(ctx, resource, action, resourceID)` (`pkg/api/grpc/service.go`) | emits an `audit.Event` (`Outcome: OutcomeAllow`/`OutcomeDeny`) on every call — see Observability |
| QUIC | Same as REST — HTTP/3 on the unified REST listener, no separate package | |
| MCP | `Server.authorizeMethod` / the `methodPermissions` table (`pkg/api/mcp/authz.go`) | fails closed at `NewServer` if RBAC is enabled without a usable authorizer |

Authentication is mandatory on every transport whether or not RBAC is
enabled; RBAC only governs authorization once an identity is established.

## Role assignment mechanism

There is exactly one entry point: `xkmsctl user register <username> --role
<name>` (`cmd/xkmsctl/user.go`), or the admin-enrollment commands
(`cmd/xkmsctl/admin.go`), which always assign `RoleAdmin`. Server-side,
`XKMSService.CreateUser` (`pkg/xkms/servicer_user.go`) resolves the role
name to a qrdb role ID via `roles.ListRoles` and an exact name match — the
role must already exist (one of qrdb's built-ins; xkms creates none). The
**first** user ever registered always receives `admin`, regardless of
`--role`. There is no `xkmsctl user assign-role` or equivalent, and
`xkmsctl user update` only toggles `--enable`/`--disable`
(`pkg/api/rest/user_handlers.go:handleUpdateUser`, body `{enabled: *bool}`).

Role CRUD (defining a **custom** role beyond the built-ins) is reachable
only through the embedded Go SDK:

```go
import xkms "github.com/jeremyhahn/go-xkms/sdk/go"

ac := xkms.Auth(qrdbClient) // qrdbClient backed by the embedded node
ac.Roles()       // qrdb RoleClient: CreateRole, GetRole, UpdateRole, DeleteRole, ListRoles, AssignRole, ...
ac.Permissions() // qrdb PermissionClient: the permission registry
ac.RBAC()        // qrdb RBACClient: Authorize, ListPermissions
```

(`sdk/go/auth.go:Auth`.) xkms contributes no CLI verb, REST route, gRPC RPC,
or MCP tool for role CRUD; every accessor above is qrdb's own client,
re-exported verbatim so a downstream consumer needs a single import.

## Test strategy

- **Unit** — `pkg/auth` (authorizer, permissions; `authmethod_test.go`
  pins the permitted-method policy, including the empty-policy case, through
  the production `QRDBUserStore` and `MTLSAuthenticator`); `pkg/apimodule/module_scopes_test.go`
  (`TestEveryModulePermissionDeclaresItsScope`, `TestModuleDeclaresOnlyItsOwnScopes`,
  `TestModuleScopeDeclarationsAreAllContributed`, `TestUndeclaredPermissionHasNoScope`).
- **Vocabulary consistency** — `internal/authzscan` builds a checked-in
  resource:action table from the gRPC/QUIC source (the two transports that
  gate per call site rather than per table), rejecting a raw string literal
  or an unrecognized `pkg/auth` constant name; `pkg/api/grpc/authz_golden_test.go`
  is the golden test built on it.
- **Request-tenant confinement** — `pkg/xkms/servicer_pkcs11state_tenant_test.go`
  and `pkg/xkms/servicer_audit_tenant_test.go`. The audit tests decide
  `audit:read:cross` from qrdb's real built-in grant table
  (`qrdbsdk.HasPermissionRoleGrant`) and apply its `ScopeCross` rule.
- **Tenant binding** — `pkg/xkms/tenant_binding_test.go` drives the service
  layer against go-qrdb's real TenantService over an in-memory barrier:
  tenant A → B refused as not-found for get, delete, barrier init / unseal /
  status and both plan changes; the refusal equals a genuine miss; A → A
  allowed except plan changes; the system identity reaches every tenant;
  `ListTenants` is filtered; `BarrierEnableEncryption` and `SignCSR` bind
  their targets. Transport mapping to not-found is pinned per transport:
  `pkg/api/rest/handlers_tenant_test.go`
  (`TestTenantHandlers_CrossTenantRefusalMatchesGenuineMiss`,
  `TestTenantHandlers_PlanChangeRefusedForTenantScope`),
  `pkg/api/grpc/service_tenant_isolation_test.go`
  (`TestTenantRPCs_CrossTenantBinding`), and
  `pkg/api/mcp/handlers_tenant_admin_test.go`
  (`TestHandleGetTenant_CrossTenantRefusalMatchesGenuineMiss`,
  `TestHandleUpdateTenantPlan_TenantScopedRefused`).
- **Role identifiers, against a real node** — `testutil.NewFirstBootNode`
  (`pkg/testutil/firstbootnode.go:50`) boots an in-memory qrdb node and runs
  qrdb's own first-boot. `ProvisionTenant` (`:95`) adds a tenant with its
  own built-in roles, and `RoleID` (`:124`) reads back the identifier a
  seeded user record would carry. The tests built on it check each former
  name-comparison site. A seeded Admin (or SO) identifier is allowed, a
  lesser role is refused, and a name-bearing identity gets nothing:
  `pkg/auth/rolemembership_test.go`,
  `pkg/xkms/servicer_password_test.go` (`TestCheckSharedPasswordOwnership_*`,
  `TestPassword{Update,Delete}_SharedOwnership*`),
  `pkg/xkms/servicer_ca_test.go` (`TestSignCSR_SeededAdminRoleIDSigns`),
  `pkg/api/mcp/authz_roleid_test.go` (`certs:generate` at the gate), and
  `pkg/api/tenantgate/tenantgate_test.go`. A fake that grants by role name
  cannot catch this class of defect: in the fake, the name and the
  identifier are the same string.
- **Makefile targets** — `test-auth`, `coverage-auth`.

## Observability

gRPC's `Service.authorize` (`pkg/api/grpc/service.go`) emits a structured
`audit.Event{Subject, Action, Resource, ResourceID, Outcome, Details:
{"transport": "grpc"}}` on **every** authorization decision, allow or deny.
On deny, `Details["reason"]` additionally carries the denying error's text
(the qrdb `PermissionDeniedError` or `ErrUnauthenticated`'s message) —
that is the only place the reason is recorded; the client response carries
only the fixed generic message (go-xkms#1103, see Error semantics).
REST's `RBACMiddleware` and MCP's authorization gate log via structured
`slog` (`Warn` on denial, `Debug` on grant) but do not construct an
`audit.Event` record — verified: neither `pkg/api/rest/rbac_middleware.go`
nor `pkg/api/mcp/authz.go` references the `audit` package. This is an
asymmetry across transports worth knowing about if you are building
detection on the `audit.Event` stream specifically rather than on logs.
