# RBAC — Engineering Contract

> **Status: NORMATIVE** · Feature: `rbac` · Repo: `go-xkms` · Last verified: 2026-10-12 (#1114, #1115, #1226, #1227, #1230, #1232, #1249, #1406, #1433)

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

`ownTenant(ctx, op, requested)` (`pkg/xkms/tenant_binding.go:86`) resolves
the tenant an operation acts in through `auth.OwnTenant`
(`pkg/auth/auth.go:133`), which delegates to `qrdbsdk.OwnTenant`: the
caller's own tenant, which `requested` may name or leave empty. Naming any
other tenant is refused, and the system tenant gets no exception: a
system-tenant identity naming another tenant is refused like any other
(go-xkms#1406). A caller with no identity is the system tenant — in-process
SDK callers carry none — and is confined to it the same way.
`admitTenantRecord(ctx, op, target)` (`:101`) guards the tenant registry,
which is the system tenant's: through `auth.AdmitTenant` (`pkg/auth/auth.go:145`)
a system-tenant caller passes for any record, every other caller only for its
own. Plan management and every operation on platform-global state admit only
a system-tenant caller, checked with `qrdbsdk.IdentityIsSystemTenant` at the
call site and refused through `refuseTenant` (`:59`). Every refusal is a
`*TenantBindingError` (`:35`), which is exactly what the composed go-qrdb
TenantService returns for an unknown tenant: same sentinel, same message
(`:47`, `:53`). Every transport already answers that sentinel with its
not-found status, so a foreign tenant ID is indistinguishable from an unused
one. The fields exist for server-side diagnostics (`errors.As`) and are never
rendered.

The binding is applied once, in `XKMSService`, and no transport repeats it:

| Method | Check | Site |
|---|---|---|
| `GetTenant` | `admitTenantRecord` | `pkg/xkms/servicer_tenant.go:91` |
| `ListTenants` | filters with `admitTenantRecord` | `pkg/xkms/servicer_tenant.go:123` |
| `DeleteTenant` | `admitTenantRecord` | `pkg/xkms/servicer_tenant.go:140` |
| `UpdateTenantEntitlements` | `qrdbsdk.IdentityIsSystemTenant` | `pkg/xkms/servicer_tenant.go:165` |
| `UpdateTenantQuotas` | `qrdbsdk.IdentityIsSystemTenant` | `pkg/xkms/servicer_tenant.go:192` |
| `SignCSR` | `ownTenant` when `TenantID` is set (the SPIFFE tenant SAN) | `pkg/xkms/servicer_ca.go:175` |
| `IssueCertificate` | `ownTenant` when `TenantID` is set | `pkg/xkms/servicer_ca.go:406` |
| `RevokeCertificate` | `ownTenant` on the certificate's issuing tenant | `pkg/xkms/servicer_ca.go:478` |
| `RotateScopeKeys` | `ownTenant` (every caller rotates its own tenant) | `pkg/xkms/servicer_keyversion.go:207` |
| `SealStorePut` / `Get` / `Delete` / `List` / `Reseal` / `Status` | `qrdbsdk.IdentityIsSystemTenant` (#1226) | `pkg/xkms/servicer_seal_store.go:50,68,93,112,130,149` |
| `SubmitCredential`, `ListCredentials` | `qrdbsdk.IdentityIsSystemTenant` (#1226) | `pkg/xkms/servicer_credentials.go:35,78` |
| `SetSOPIN`, `SetUserPIN`, `ChangeSOPIN`, `ChangeUserPIN`, `VerifySOPIN`, `VerifyUserPIN`, `GetLockoutStatus`, `ResetLockout` | `qrdbsdk.IdentityIsSystemTenant` (#1227) | `pkg/xkms/servicer_pin.go:46,58,70,82,94,106,118,146` |
| `ListPIVSlots`, `GetPIVCertificate`, `StorePIVCertificate`, `DeletePIVCertificate`, `GeneratePIVKey`, `ImportPIVCertificate`, `ExportPIVCertificate`, `GeneratePIVCSR` | `qrdbsdk.IdentityIsSystemTenant` (#1227) | `pkg/xkms/servicer_piv.go:33,42,51,60,69,78,87,96` |
| `TrustRoot*` | `qrdbsdk.IdentityIsSystemTenant` | `pkg/xkms/servicer_trust_roots.go:42` |
| `GetTenantTPMMode`, `SetTenantTPMMode`, `TenantVTPMStatus` / `Start` / `Stop` | `qrdbsdk.IdentityIsSystemTenant` | `pkg/xkms/servicer_tpm_policy.go:53` |
| `TPMPolicy*`, `TPMObjectPolicy` | `ownTenant` (every caller, the system tenant included, acts on its own tenant) | `pkg/xkms/servicer_tpm_policy.go:40` |

The platform-scoped rows are reached on every transport only through the
service: the REST handlers (`pkg/api/rest/seal_store_handlers.go`,
`handlers_credentials.go`, `handlers_pin.go`,
`handlers_barrier_shamir.go`, `handlers_piv.go`, `policy_handlers.go`), the
gRPC/Unix handlers (`pkg/api/grpc/service_seal_store.go`,
`service_pin.go`, `service_barrier_shamir.go`, `service_piv.go`,
`service_policy.go`) and the MCP handlers (`pkg/api/mcp/handlers_seal_store.go`,
`handlers_init_credentials.go`, `handlers_barrier_shamir.go`,
`handlers_pin.go`, `handlers_piv.go`, `handlers_policy.go`) hold the
`XKMSService` and never the store, barrier, PIN backend, policy manager,
credential service or package-level PIV functions. `rest.Config` and
`mcp.Config` no longer carry those subsystems at all.

SSH assets take the same rule one level down, in the SSH service rather than
`XKMSService` (go-xkms#1230). Their address is `(scope, owner, name)`, and
the owner may be a user as well as a tenant, so `pkg/ssh/tenancy` binds it:
a tenant-scoped identity owns `scope=tenant` only for `owner ==
identity.TenantID` and `scope=user`/`service` only for `owner ==
identity.Subject`, a system-tenant identity included — there is no
platform caller that owns every address (go-xkms#1406), and a request with no
identity is refused (`pkg/ssh/tenancy/client.go:275-285`). The refusal, `*OwnerBindingError`
(`pkg/ssh/tenancy/errors.go:44-71`), is the SSH store's own not-found for the
address, verbatim — the SSH counterpart of `TenantBindingError`. Every
transport's SSH surface calls that one service (`pkg/server/server.go:486-512`);
none repeats the check. See
[`../ssh-keys/architecture.md`](../ssh-keys/architecture.md) §"Owner binding
and tenant partitions".
The ACME admin plane (`pkg/acme/admin`) is served by its own service, not
`XKMSService`, and carries its own binding with the same convention
(go-xkms#1225): `admitTenant` (`pkg/acme/admin/tenant_binding.go:105`), over
`auth.AdmitTenant`, and a `qrdbsdk.IdentityIsSystemTenant` check that refuses
with `*PlatformScopeError` (`:63`) for platform-only operations. Its
`*TenantBindingError` unwraps to that package's `ErrTenantNotFound` and reads
as a missing tenant. It also checks that a role or user belongs to the tenant
the path names before touching it, scopes ACME certificates, accounts and
orders by the caller's tenant, and binds the caller's tenant as the qrdb
context tenant at its authentication boundary (`pkg/acme/admin/auth.go:101`).
The full contract is in
[`../acme-issuance/engineering.md`](../acme-issuance/engineering.md#invariants).


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
`generate`, `revoke`, `read`, `update`, `set_entitlements`, `set_quotas`,
`write`, `use`, `disable`, `status`,
`capabilities`, `bootstrap`, `seal`, `unseal`, `rekey`, `rotate_root_key`,
`generate_recovery`, `recover_with_keys`, `initialize_shamir`,
`unseal-share`, `enable_encryption`, `init`, `claim_cert`,
`claim_share_begin`, `claim_share_complete`, `sign_csr`,
`enroll_custodian`, `revoke_custodian`, `submit`, `strategy`, `lock`,
`unlock`.

There is no cross-tenant audit action: go-qrdb v0.28 removed
`audit:read:cross`, and `TestAudit_NoCrossTenantRead`
(`pkg/auth/permissions_test.go`) fails if qrdb's registry knows it again.

### `pkg/xkms` — the service's Authorizer

```go
func (s *XKMSService) SetAuthorizer(a *auth.Authorizer)
```

The server passes it the transports' own Authorizer. The service uses it for
decisions the route gate cannot make, through `AuthorizeCaller` (a feature's
explicit permission below the gate, such as `ssh:service`). A nil Authorizer
is RBAC-disabled, as everywhere else. `QueryAudit` does not consult it: an
audit query's tenant is always the caller's own.

A permission is a `resource:action` pair. A transport must never declare its
own resource or action string literal — `internal/authzscan` enforces this by
parsing a transport's own source (there is no separate QUIC transport; the
legacy per-transport listeners, including `pkg/api/quic`, were removed
wholesale) and rejecting a raw string literal or an unknown constant name
(see Test strategy). `internal/authzscan.Scan` covers the per-call-site
transports — gRPC's `s.authorize(...)` calls, REST's `routes.go` route-table
helper calls, and `pkg/acme/admin`'s `adminRoute`/`tenantRoute`/`tenantCrossRoute`
route-table entries (`pkg/acme/admin/routes.go:97-174`) —
`internal/authzscan.ScanMap` covers the `handle(...)` registrations in MCP's
`rpcMethods` table directly, and `pkg/api/authz_consistency_test` cross-checks all three
against a hand-built capability table so the same capability cannot require
different permissions on different transports (go-xkms#1232).

### `cmd/xkmsctl/user.go` — CLI role names

xkmsctl defines no role type of its own. `user register --role` sends the
role name as given (`cmd/xkmsctl/user.go:205-207`): a built-in name
(`qrdbsdk.RoleNameSO`…`RoleNameAuditor`) or a custom role the tenant holds.
The CLI does not validate it; the server resolves the name and refuses one
the tenant does not hold (`*ErrUnknownRole`). The default is
`qrdbsdk.RoleNameUser`, and the first user registered is always
`qrdbsdk.RoleNameAdmin` (`cmd/xkmsctl/user.go:217`).

### `pkg/apimodule/module_scopes.go` — the permissions xkms alone scopes

Since go-qrdb#504 removed the implicit default, every permission must
declare a tenancy scope (`self` / `tenant-only` / `cross`) or the authorizer
refuses it. qrdb declares the scope of its own canonical vocabulary; xkms
declares scope **only** for the resource:action pairs it alone owns — nine
names, all `ScopeSelf`:

```go
func selfScopedPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		"keys:update",     // PKCS11StateCAS + SealStoreReseal (system-barrier state)
		"bootstrap:read",  // the trust-bootstrap listener's own public keys (go-xkms#632)
		"policy:create",   // TPM 2.0 PCR-bank sealed-secret policy management
		"policy:get",      // (pkg/seal/policy, go-xkms#691) — platform/hardware
		"policy:list",     // state, not per-tenant key material, so it takes the
		"policy:delete",   // same reach as keys:update and bootstrap:read above.
		"policy:refresh",
		"policy:verify",
		"policy:export",
	}
}
```

go-xkms#1249 retired `keys:read` and `keys:write`: the PKCS#11 state store
and the platform-sealed store now carry the ordinary per-verb
`keys:create`/`get`/`list`/`delete` actions qrdb itself declares scope for
on every transport, leaving `keys:update` (the compare-and-swap /
reseal-in-place operations) as the only member of that family qrdb does not
declare.

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
  never string literals**, on every transport — enforced by
  `internal/authzscan`, which scans gRPC's, REST's, and `pkg/acme/admin`'s
  call sites (`authzscan.Scan`) and the `handle(...)` registrations in MCP's
  `rpcMethods` table directly (`authzscan.ScanMap`). REST's `routes.go` briefly carried three
  raw literals (`"derive"`, `"wrap"`, `"unwrap"`) with no test to catch them
  until go-xkms#1232 added `pkg/api/rest/authz_golden_test.go`.
- **The same capability requires the same permission on every transport
  that exposes it.** `pkg/api/authz_consistency_test` cross-checks a
  hand-built capability table against all three transports' own golden
  tables; go-xkms#1232's audit found and fixed one violation
  (`POST /api/v1/keys/wrap`/`unwrap` carried `keys:encrypt`/`keys:decrypt`
  instead of the `keys:wrap`/`keys:unwrap` gRPC and MCP already required for
  the identical operation). go-xkms#1249 fixed two more: the
  `pkcs11state.*`/`sealStore.*` families' REST per-verb CRUD actions vs
  gRPC's (and, for `sealStore.*`, MCP's) coarser write/read tiering, by
  moving every transport onto the per-verb actions; and `EnableUser`/
  `DisableUser` (gRPC) and `user.enable`/`user.disable` (MCP) requiring the
  borrowed `users:update` while REST's single `PUT /api/v1/users/{username}`
  route also gated both directions on `users:update` because it could not
  see which direction a request meant before the permission gate ran — fixed
  by splitting REST into `POST /api/v1/users/{username}/enable` and
  `.../disable`, one route per qrdb-native permission
  (`users:enable`/`users:disable`), matching gRPC and MCP exactly; `PUT`
  no longer touches `enabled` at all. A third violation, `POST
  /api/v1/passwords/access-mode` serving under session-only auth with no
  RBAC permission where gRPC/MCP required `passwords:write`, was left open
  pending a product decision until the owner ruled (2026-09-29) that the
  password vault is not a login feature; REST now gates it on
  `passwords:write` too. No violations remain allowlisted.
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
  (`pkg/auth/mtls.go`) with go-qrdb's own `qrdbsdk.CheckAuthMethod` -- the
  function qrdb's authentication middleware runs, so xkms carries no copy of
  the rule: an **empty policy states no restriction**, the method and every
  stored entry are compared in `qrdbsdk.CanonicalAuthMethod` form (trimmed,
  lowercased; a stored entry is not checked against the vocabulary, so a
  legacy entry still matches), and a blank method matches nothing and is
  refused. A refused
  account is never admitted through the certificate-field fallback that
  serves certificates when no `UserStore` is configured — a `UserStore`
  configuration never falls back to certificate fields at all, whether the
  refusal is disablement, policy exclusion, or an unbound certificate.
  The WebAuthn relying party applies the same `qrdbsdk.CheckAuthMethod` with
  `qrdbsdk.MethodWebAuthn`, and the PIV login (`POST /api/v1/auth/piv`) with
  `qrdbsdk.MethodPIV` -- distinct from `mtls`, so an account can be permitted
  one without the other (go-xkms#1095) -- alongside the lifecycle check, through
  `webauthn.CheckAccountStanding` (go-xkms#1298; see
  [webauthn/engineering.md](../webauthn/engineering.md)).
- **A tenant ID taken from a request is bound in `XKMSService`, never in a
  transport.** The RBAC gate cannot do it (see `Authorize` above); a
  transport-level copy is a second owner that drifts. A new service method
  that targets a caller-supplied tenant calls `ownTenant` (or checks
  `qrdbsdk.IdentityIsSystemTenant`) and gets a row in the table above.
- **Plan management is platform-only.** Entitlements and quotas are gated on
  qrdb's dedicated `tenants:set_entitlements` / `tenants:set_quotas`
  (`pkg/auth/permissions.go:154-155`), never `tenants:update`, on every
  transport: `pkg/api/rest/routes.go:300-301`, `pkg/api/mcp/server.go:375-376`,
  `pkg/api/grpc/service_tenant.go:896,922`, and the
  `qrdb.v1.permission` options at `pkg/api/grpc/proto/xkmsv1/xkms.proto:647,654`.
  Because both permissions are self-scoped in qrdb and qrdb's built-in Admin
  role grants `tenants:set_entitlements`, the RBAC gate alone would still
  let a Tenant Admin change its own plan; `qrdbsdk.IdentityIsSystemTenant` is what
  refuses it.
- **Platform-global state is platform-only.** The sealed platform store and
  the backend credentials in it, the system barrier, the token PINs, the
  server's PIV card and the PCR policies belong to no tenant, and their
  permissions (`keys:*`, `credentials:submit`, `seal:*`, `barrier:*`,
  `pin:*`, `piv:*`, `policy:*`) are self-scoped, so a tenant-local Admin
  passes the gate for all of them (go-xkms#1226, #1227). Each service method
  checks `qrdbsdk.IdentityIsSystemTenant` before it touches the subsystem, and each
  transport reaches the subsystem only through that method. A new operation
  on one of these subsystems adds a row to the table above and an entry to
  `platformScopedOps` (`pkg/xkms/platform_scope_test.go`).
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
- **No role is exempt from tenant scoping, and no tenant either.**
  `tenantgate.Access` consults no role: a nil or system-tenant identity
  passes it with no tenant barrier (`pkg/api/tenantgate/tenantgate.go:116`),
  and that grants no reach — the service binding and `pkg/scope` still
  confine it to the system tenant (go-xkms#1406). `auth.IsCrossTenant` is
  left only for tenant IAM administration in `pkg/acme/admin`.
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
  is hosted) derives an identity from certificate fields: the subject is
  the CN, else the first DNS SAN, else the serial (`defaultExtractSubject`,
  `mtls.go:330-341`); the tenant is the first OU (`certIdentity`,
  `mtls.go:282-283`); and it carries no roles, so with RBAC enabled it holds
  no grants.

- **The OIDC authenticator bounds what it reads from the identity
  provider.** The discovery document, the JWKS and the userinfo response are
  each read through `readOIDCResponse` (`pkg/auth/oidc.go:50`), which
  refuses a body over 1 MiB (`maxOIDCResponseBytes`, `oidc.go:46`) with
  `ErrOIDCResponseTooLarge` (`oidc.go:94`) instead of buffering it.

## Error semantics

| Error | Where | Meaning |
|---|---|---|
| `ErrUnauthenticated` | `pkg/auth/errors.go` | `Authorize` called with a nil identity while enabled |
| `*qrdbsdk.AuthMethodNotPermittedError{Username, TenantID, Method, Permitted}` | go-qrdb `sdk/go` | the certificate resolved to an active account whose permitted-method policy excludes `mtls`; it is qrdb's own error type, the one its middleware returns, so a refusal reads the same on every plane |
| `ErrCertNotBound` | `pkg/auth/errors.go:48` | mTLS authenticator with a `UserStore`: the client certificate's SPKI thumbprint is bound to no user. The request is unauthenticated (REST 401), and the gate never runs |
| `*UserLookupError{Err}` | `pkg/auth/errors.go:85` | mTLS authenticator with a `UserStore`: the store failed for any reason other than a definite not-found. It fails closed, and `Err` carries the store's error |
| `*xkms.TenantBindingError` | `pkg/xkms/tenant_binding.go:34` | a tenant-scoped caller named another tenant (or the system scope), or asked for a plan change; unwraps to `qrdbsdk.ErrTenantMissing` and renders as not-found on every transport |
| qrdb's `PermissionDeniedError` | returned by `rbac.Authorize` | grant missing, or tenant scope gate rejects the request |
| `ErrAuthorizerRequired` | `pkg/api/rest/errors.go` | `rest.NewServer` refuses to construct when `EnableRBAC` is true but no usable authorizer was supplied — fails closed at construction, never falls back to allow-all |
| `*ErrUnknownRole{Role}` | `pkg/xkms/errors.go` | `CreateUser`'s role name does not match any existing qrdb role, wrapped in `*ErrUserOperation{Operation: "resolve role"}` |
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
rule). RBAC works with every datastore configuration (standalone or
remote) now that every deployment is qrdb-backed — see architecture.md and
[`../datastore/engineering.md`](../datastore/engineering.md).

```yaml
datastore:
  engine: "pebble"
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
| REST | `RBACMiddleware.RequirePermission(resource, action)` (`pkg/api/rest/rbac_middleware.go`), applied per `RouteSpec` in `pkg/api/rest/routes.go` where `Auth == RouteAuthPermission`, ahead of the route's body bound (`pkg/api/rest/server.go:563-565`), so a denied caller gets 403 before its body is read | table-driven; a route's `Enabled` guard can also remove it entirely when its subsystem is unconfigured |
| gRPC | `Service.authorize(ctx, resource, action, resourceID)` (`pkg/api/grpc/service.go`) | emits an `audit.Event` (`Outcome: OutcomeAllow`/`OutcomeDeny`) on every call — see Observability |
| QUIC | Same as REST — HTTP/3 on the unified REST listener, no separate package | |
| MCP | `Server.authorizeMethod` (`pkg/api/mcp/authz.go`), reading the permission each `rpcMethods` entry registers with `handle` (`pkg/api/mcp/server.go`) | fails closed at `NewServer` if RBAC is enabled without a usable authorizer |

Authentication is mandatory on every transport whether or not RBAC is
enabled; RBAC only governs authorization once an identity is established.

MCP reports a missing identity as JSON-RPC `-32002` and a missing grant as
`-32003` (`ErrCodeUnauthorized`, `ErrCodeForbidden`,
`pkg/api/mcp/types.go:65`, `:72`). The only public methods are `health`,
`xkms.algorithms`, `invite.get` and `invite.pivActivate`, the same ones REST
serves unauthenticated; they are the only entries registered with
`handlePublic` (`pkg/api/mcp/server.go:250`, `:256`, `:407-408`). A method
missing from `rpcMethods` has no handler, so it is refused as
`ErrCodeMethodNotFound`; there is no dispatchable method without a
permission.

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
(`pkg/api/rest/user_handlers.go:handleEnableUser`/`handleDisableUser`,
`POST /api/v1/users/{username}/enable`/`.../disable`, no body).

For mTLS, `xkmsctl admin create <username> --method mtls --cert-file
<pem>` creates the user and binds the certificate in one step: the binding
holds the certificate's SPKI thumbprint (`qrdbsdk.ComputeSPKIThumbprint`,
`cmd/xkmsctl/admin.go:202`) and its `NotAfter` (`:247-248`), so a reissued
certificate for the same key still resolves. `--pkcs11-module` reads the
certificate from a token instead (`admin.go:741-742`).

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
  resource:action table from each transport's own source, rejecting a raw
  string literal or an unrecognized `pkg/auth` constant name:
  `pkg/api/grpc/authz_golden_test.go` (gRPC's `authorize` call sites),
  `pkg/api/rest/authz_golden_test.go` (REST's `routes.go` route-table helper
  calls), `pkg/acme/admin/authz_golden_test.go` (the route-table entries), and
  `pkg/api/mcp/authz_golden_test.go` (the `handle(...)` registrations in
  `rpcMethods`, via `authzscan.ScanMap`). `internal/authzscan_test.go` covers the scanner
  itself, including the raw-literal and unknown-constant rejection paths.
- **Cross-transport consistency** — `pkg/api/authz_consistency_test`
  (`TestCapabilities_RequireSamePermissionOnEveryTransport`) re-derives the
  gRPC, REST, and MCP tables with `internal/authzscan` and asserts every
  capability named in its `canonicalCapabilities` table resolves to the
  identical `resource:action` pair on every transport that exposes it, so a
  capability that drifts on only one transport fails even though that
  transport's own golden test still passes.
- **Request-tenant confinement** — `pkg/xkms/servicer_pkcs11state_tenant_test.go`
  and `pkg/xkms/servicer_audit_tenant_test.go`. The audit tests prove every
  caller, the system tenant included, is confined to its own tenant under an
  admitting Authorizer that is never consulted.
- **Tenant binding** — `pkg/xkms/tenant_binding_test.go` drives the service
  layer against go-qrdb's real TenantService over an in-memory barrier:
  tenant A → B refused as not-found for get, delete, barrier init / unseal /
  status and both plan changes; the refusal equals a genuine miss; A → A
  allowed except plan changes; the system (or an absent) identity reaches
  every tenant record but is refused every other tenant's target
  (`TestBindTenantRecord_SystemOwnsTheRegistry`,
  `TestTargetTenant_ConfinesEveryCaller`); `ListTenants` is filtered; `BarrierEnableEncryption` and `SignCSR` bind
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
