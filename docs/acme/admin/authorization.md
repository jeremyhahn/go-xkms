# Admin API Authorization

The ACME Admin API carries **no authorization model of its own**. Every decision
is delegated to the hosted go-qrdb node's RBAC service through the xkms
`auth.Authorizer` — the same seam the xkms REST, gRPC, QUIC, and MCP transports
use. A role grant therefore means exactly the same thing on the ACME Admin API
as it does everywhere else in the stack.

This replaced a parallel vocabulary (`super-admin` / `admin` / `endorser` /
`operator` / `viewer`, with permissions such as `manage_tenants`,
`manage_root_ca`, and `system_config`) that shared no members with the canonical
qrdb roles. Granting someone `admin` in qrdb conferred no ACME admin rights, and
revoking it removed none.

## Authorization Model

```
Request
   |
   v
Authentication              JWT (admin.AuthMiddleware) or
                            mTLS client certificate (admin.MTLSAuthMiddleware) or
                            SO_PEERCRED on the gRPC Unix socket (server.RoleMapping)
   |
   | publishes auth.Identity{Subject, TenantID, Roles} on the request context
   v
admin.PermissionGate        resolves resource:action for the route / method
   |
   v
auth.Authorizer             xkms seam, no local policy
   |
   v
go-qrdb RBAC service        canonical policy decision point
   |
   v
Allow / Deny                deny is the default on every failure path
```

Three properties hold on every surface:

- **Authentication is mandatory.** A request with no identity is `401` /
  `Unauthenticated`, regardless of whether RBAC is enabled.
- **Unmapped operations are denied.** A dispatchable gRPC method or MCP method
  with no entry in its permission table is refused, never served.
- **An unwired gate denies.** A nil `PermissionGate` — a composition bug — fails
  closed.

When the `Authorizer` has no RBAC client (RBAC disabled, or no qrdb identity
plane is hosted), authorization is disabled and an authenticated caller is
admitted. This matches the documented stack-wide "RBAC disabled => allow all"
posture of `pkg/api/rest` (QUIC is HTTP/3 served on the same REST listener,
so it shares this posture; there is no separate `pkg/api/quic` server
package).

## Roles

The canonical go-qrdb roles are the only roles. There is no ACME-specific role.

| Role | ACME admin reach |
|---|---|
| `so` | Full: CA hierarchy, ACME accounts / orders / EABs, barrier governance, role management |
| `admin` | Full ACME administration; CA hierarchy; tenant, user, certificate, and EAB lifecycle. Not barrier bootstrap/rekey/root-token, not role mutation |
| `operator` | Read-only ACME registration data and CA hierarchy; barrier seal/unseal/status |
| `user` | None |
| `auditor` | Read-only ACME registration metadata, CA hierarchy, certificates, tenants, and the audit trail |
| `custodian` | `barrier:unseal-share` only |

The deleted `endorser` role expressed exactly one authority: minting External
Account Bindings. A deployment that needs an endorse-only principal creates a
qrdb role holding `acme_eab:create` and nothing else. No seventh canonical role
was added.

Cross-tenant reach follows qrdb's **system-tenant rule**: an identity rooted in
the reserved system tenant, or one carrying no tenant at all (empty
`TenantID` -- the bootstrap case), is platform-scoped and reaches every
tenant; any other identity is confined to its own. This replaced the local
"super-admin can access any tenant" check, and is implemented by
`auth.IsCrossTenant` / `admin.RequireTenantScope`.

## Permission vocabulary

All permissions are canonical go-qrdb `resource:action` pairs. xkms mirrors the
names it uses in `pkg/auth/permissions.go`; it registers no vocabulary of its
own.

Reused from qrdb's existing registry:

| Resource | Actions | Used for |
|---|---|---|
| `certs` | `list`, `read`, `revoke` | ACME-issued X.509 certificates |
| `tenants` | `create`, `read`, `update`, `delete`, `list` | Tenant lifecycle |
| `roles` | `create`, `read`, `update`, `delete`, `list` | Tenant role administration |
| `users` | `create`, `read`, `update`, `delete`, `list` | Tenant user administration |
| `audit` | `read` | Audit trail |
| `admin` | `status`, `capabilities` | Server status/stats, algorithm discovery |
| `seal` | `bootstrap`, `seal`, `unseal`, `status`, `rekey`, `rotate_root_key`, `generate_recovery`, `recover_with_keys`, `initialize_shamir` | Barrier lifecycle |
| `barrier` | `unseal-share` | Shamir share submission |

Added to go-qrdb (`pkg/permission/acme_admin_scope.go`), because no existing
resource expressed the authority:

| Resource | Actions | Why it is not a duplicate |
|---|---|---|
| `acme_accounts` | `read`, `list`, `disable` | An ACME account is a JWK-keyed protocol registration, not a certificate (`certs`) or a platform user (`users`) |
| `acme_orders` | `read`, `list` | An order is an issuance request, distinct from the certificate it produces |
| `acme_eab` | `read`, `list`, `create`, `delete` | An External Account Binding is a pre-shared enrolment credential. Separating it is what lets a deployment mint a narrow endorse-only role |
| `ca` | `create`, `read`, `list`, `update` | CA *hierarchy* lifecycle. Strictly more privileged than `certs:*`, which is *leaf* certificate lifecycle — holding `certs:generate` must not imply authority to mint a signing CA |

These take the default `ScopeSelf`, so the system-tenant rule lifts them across
tenants for a platform admin. They are deliberately **not** `ScopeTenantOnly`
like the broker's `acme:read` / `acme:write`, which model a tenant's own ACME
issuance settings and are denied to the platform operator by design.

They are re-exported through the qrdb SDK as `qrdbsdk.PermissionACMEAccountsRead`,
`PermissionCACreate`, and so on.

## Operation mapping

### REST — `/admin/*`

| Method | Path | Permission |
|---|---|---|
| GET | `/admin/certificates` | `certs:list` |
| GET | `/admin/certificates/expiring` | `certs:list` |
| GET | `/admin/certificates/{serial}` | `certs:read` |
| POST | `/admin/certificates/{serial}/revoke` | `certs:revoke` |
| GET | `/admin/accounts` | `acme_accounts:list` |
| GET | `/admin/accounts/{id}` | `acme_accounts:read` |
| DELETE | `/admin/accounts/{id}` | `acme_accounts:disable` |
| GET | `/admin/orders` | `acme_orders:list` |
| GET | `/admin/orders/{id}` | `acme_orders:read` |
| GET | `/admin/audit` | `audit:read` |
| GET | `/admin/status` | `admin:status` |
| GET | `/admin/stats` | `admin:status` |
| GET | `/admin/algorithms` | `admin:capabilities` |

### REST — `/api/v1/tenants/*`

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/tenants` | `tenants:list` |
| POST | `/api/v1/tenants` | `tenants:create` |
| GET | `/api/v1/tenants/{id}` | `tenants:read` |
| PUT | `/api/v1/tenants/{id}` | `tenants:update` |
| DELETE | `/api/v1/tenants/{id}` | `tenants:delete` |
| PUT | `/api/v1/tenants/{id}/status` | `tenants:update` |
| POST | `/api/v1/tenants/{id}/root-ca` | `ca:create` |
| GET | `/api/v1/tenants/{id}/intermediate-cas` | `ca:list` |
| POST | `/api/v1/tenants/{id}/intermediate-cas` | `ca:create` |
| GET | `/api/v1/tenants/{id}/intermediate-cas/{caid}` | `ca:read` |
| PUT | `/api/v1/tenants/{id}/intermediate-cas/{caid}/status` | `ca:update` |
| PUT | `/api/v1/tenants/{id}/default-intermediate-ca` | `ca:update` |
| GET | `/api/v1/tenants/{id}/ca-status` | `ca:read` |
| GET | `/api/v1/tenants/{id}/eab` | `acme_eab:list` |
| POST | `/api/v1/tenants/{id}/eab` | `acme_eab:create` |
| GET | `/api/v1/tenants/{id}/eab/{kid}` | `acme_eab:read` |
| DELETE | `/api/v1/tenants/{id}/eab/{kid}` | `acme_eab:delete` |
| GET | `/api/v1/tenants/{id}/roles` | `roles:list` |
| POST | `/api/v1/tenants/{id}/roles` | `roles:create` |
| GET | `/api/v1/tenants/{id}/roles/{roleID}` | `roles:read` |
| PUT | `/api/v1/tenants/{id}/roles/{roleID}` | `roles:update` |
| DELETE | `/api/v1/tenants/{id}/roles/{roleID}` | `roles:delete` |
| GET | `/api/v1/tenants/{id}/users` | `users:list` |
| POST | `/api/v1/tenants/{id}/users` | `users:create` |
| GET | `/api/v1/tenants/{id}/users/{userID}` | `users:read` |
| PUT | `/api/v1/tenants/{id}/users/{userID}` | `users:update` |
| DELETE | `/api/v1/tenants/{id}/users/{userID}` | `users:delete` |

### REST — `/admin/barrier/*`

| Method | Path | Permission |
|---|---|---|
| GET | `/admin/barrier/status` | `seal:status` |
| POST | `/admin/barrier/initialize` | `seal:bootstrap` |
| POST | `/admin/barrier/seal` | `seal:seal` |
| POST | `/admin/barrier/unseal` | `seal:unseal` |
| POST | `/admin/barrier/shamir/initialize` | `seal:initialize_shamir` |
| POST | `/admin/barrier/shamir/unseal-share` | `barrier:unseal-share` |
| POST | `/admin/barrier/rekey` | `seal:rekey` |
| POST | `/admin/barrier/recovery/generate` | `seal:generate_recovery` |
| POST | `/admin/barrier/recovery/recover` | `seal:recover_with_keys` |
| GET | `/admin/barrier/recovery/status` | `seal:status` |
| POST | `/admin/barrier/root-token` | `seal:rotate_root_key` |

### gRPC and MCP

`server.MethodPermissions` (gRPC) and `server.MCPMethodPermissions` (MCP) carry
the same pairs for the same operations.
`TestCrossSurface_SameOperationSamePermission` asserts the two tables agree, so
a grant cannot mean one thing over gRPC and another over MCP.

| Operation | gRPC method | MCP method | Permission |
|---|---|---|---|
| Server status | `GetStatus`, `GetStats` | `admin.getStatus`, `admin.getStats` | `admin:status` |
| Certificates | `ListCertificates` / `GetCertificate` / `RevokeCertificate` | `admin.listCertificates` / `admin.getCertificate` / `admin.revokeCertificate` | `certs:list` / `certs:read` / `certs:revoke` |
| ACME accounts | — | `admin.listAccounts` / `admin.getAccount` / `admin.disableAccount` | `acme_accounts:list` / `:read` / `:disable` |
| Tenants | `ListTenants` / `GetTenant` / `CreateTenant` / `UpdateTenant` / `DeleteTenant` | `admin.listTenants` / `admin.getTenant` / `admin.createTenant` / `admin.updateTenant` / `admin.deleteTenant` | `tenants:list` / `:read` / `:create` / `:update` / `:delete` |
| EABs | `ListEABs` / `GetEAB` / `CreateEAB` / `DeleteEAB` | `admin.listEABs` / `admin.getEAB` / `admin.createEAB` / `admin.deleteEAB` | `acme_eab:list` / `:read` / `:create` / `:delete` |
| Roles | `ListTenantRoles` / `GetTenantRole` / `CreateTenantRole` / `UpdateTenantRole` / `DeleteTenantRole` | `admin.listRoles` / `admin.getRole` / `admin.createRole` / `admin.updateRole` / `admin.deleteRole` | `roles:list` / `:read` / `:create` / `:update` / `:delete` |
| Users | `ListTenantUsers` / `GetTenantUser` / `CreateTenantUser` / `UpdateTenantUser` / `DeleteTenantUser` | `admin.listUsers` / `admin.getUser` / `admin.createUser` / `admin.updateUser` / `admin.deleteUser` | `users:list` / `:read` / `:create` / `:update` / `:delete` |

## Identity sources

### JWT — `admin.AuthMiddleware`

Roles come from the token's `roles` claim, the tenant from `tenant_id`. Both are
published verbatim as `auth.Identity`; qrdb decides what they grant.

### mTLS — `admin.MTLSAuthMiddleware`

Roles come from the certificate's Organizational Unit values, the tenant from
Organization. Names pass through verbatim. A certificate that names no role
yields an identity with **no roles**, and every privileged operation is denied.
There is no fallback role.

### gRPC over TCP — `server.UnaryMTLSIdentityInterceptor`

Authenticates the verified TLS client certificate through the canonical
`auth.MTLSAuthenticator` (including SPKI-thumbprint user lookup when a
`UserStore` is configured) and publishes the identity. A call with no usable
client certificate carries no identity and is refused by the authorization
interceptor.

### gRPC over Unix socket — `server.RoleMapping`

`SO_PEERCRED` gives the kernel-verified UID/GID of the calling process;
`RoleMapping` maps it to canonical qrdb role names (`admin`, `operator`,
`auditor`). Defaults: UID 0 and GID 0 → `admin`; GID 10 (wheel) and GID 80
(macOS admin) → `operator`. **A peer matching no entry receives no roles** and
is denied.

## First-run setup

`/admin/setup/*` is deliberately unauthenticated: it is the first-run bootstrap
that exists before any credential does. It is bounded by
`setupService.requirePending`, which returns `SetupAlreadyCompleteError` once
setup has completed — the state is persisted in the KV store, so the window does
not reopen on restart.

## Tenant role provisioning

Tenant RBAC roles are **not** seeded by the ACME admin service. go-qrdb
provisions the six canonical system roles for every tenant it creates. The ACME
service previously seeded a second set named `admin` / `operator` / `viewer`
carrying the parallel permission vocabulary, which shadowed the canonical roles
for that tenant.

## Testing

- `pkg/acme/admin/authz_test.go` — the gate: allow, deny, no identity, unwired
  gate, disabled authorizer, tenant scope.
- `pkg/acme/admin/routes_authz_test.go` — every REST route: the exact
  `resource:action` requested, allowed with the grant, denied without it, denied
  unauthenticated, reachable by qrdb `admin`, unreachable once revoked.
- `pkg/acme/api/server/interceptor_authz_test.go` — the same matrix for gRPC,
  plus the fail-open regressions (TCP without identity, unmapped method,
  unmapped peer).
- `pkg/acme/api/server/mcp_authz_test.go` — the same matrix for MCP.
- `pkg/acme/api/server/cross_surface_authz_test.go` — the gRPC and MCP tables
  agree, and every pair is drawn from the canonical vocabulary.

The test RBAC client resolves grants from `qrdbsdk.BuiltInRoles`, so the
assertions run against go-qrdb's real role definitions rather than a
hand-written allowlist.
