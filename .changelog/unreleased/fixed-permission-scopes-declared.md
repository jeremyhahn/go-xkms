- **Every permission the xkms API module contributes to go-qrdb now declares
  its tenancy scope, so a role holding one can still obtain a token.**
  go-qrdb#504 removed the implicit self-scope: under go-qrdb v0.19.0-alpha a
  permission with no declared scope is refused rather than admitted as
  `ScopeSelf`, and `rbac.ListPermissions` fails on the *first* unscoped
  permission an identity holds — so one omission denies login, not one call.
  `pkg/apimodule/module_grants.go` registered the module's 73-permission
  vocabulary with `qrdbsdk.RegisterPermissions` and declared no scope for any
  of it. 69 of those names are go-qrdb's own and carry go-qrdb's scope; the
  four go-qrdb does not declare — `keys:read`, `keys:write`, `keys:update`,
  `ssh:use` — had none, and on go-quicbaas v0.11.0-alpha (which composes
  go-xkms v0.14.0-alpha) every login for a role carrying `keys:read` was
  rejected with `permission: no scope declared for keys:read`. The new
  `pkg/apimodule/module_scopes.go` declares those four — and only those four —
  `PermissionScopeSelf` via `qrdbsdk.RegisterPermissionScope`, pinning each by
  name with its rationale: `keys:read`/`keys:write`/`keys:update` gate the
  PKCS#11 object-state and seal stores, which hold system-barrier state, and
  go-qrdb declares the whole `seal:*` family `ScopeSelf` while reserving
  `ScopeTenantOnly` for the per-tenant `tenant_barrier:*` custody; `ssh:use` is
  the blanket gate on the SSH CA route group whose siblings `ssh:read`,
  `ssh:write`, `ssh:delete` — and the matching `piv:use` — are all `ScopeSelf`
  in go-qrdb. That is the reach all four had before go-qrdb#504, so no
  deployment's authorization outcome changes; the omission simply becomes a
  decision. Registration order in `registerRoleGrants` is now permissions →
  scope → role grants, because the authorizer resolves scope before it
  consults the grant. Files: `pkg/apimodule/module_grants.go` (permission
  derivation extracted to `modulePermissions`),
  `pkg/apimodule/module_scopes.go`, `pkg/testutil/permscope.go` (reads a
  declared scope back through the SDK's `NewTenantScopeStore`, the same
  resolution path the RBAC authorizer uses, since the SDK re-exports only the
  write side of `RegisterPermissionScope`). Tests:
  `pkg/apimodule/module_scopes_test.go` is the build gate — mirroring go-qrdb's
  `TestEveryPermissionDeclaresItsScope` — asserting that every contributed
  permission resolves a scope, that xkms declares a scope for no name go-qrdb
  already owns (`RegisterPermissionScope` overwrites, so a duplicate would
  silently replace an upstream decision), that no declaration names a
  permission the module does not contribute, and that an undeclared permission
  still surfaces `*PermissionUndeclaredScopeError` so the gate cannot pass
  vacuously; `pkg/testutil/permscope_test.go` covers the resolver against
  self-, tenant-only-, and cross-scoped built-ins plus the undeclared error
  path.
