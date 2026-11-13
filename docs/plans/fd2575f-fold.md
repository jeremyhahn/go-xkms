# fd2575f: admin role access on go-qrdb v0.58.2

- Failing tests (12): pkg/acme/admin TestACMEAdminRoutes_DeniedWithoutGrant
  (create_role, update_role), TestTenantBinding_ForeignTenantRefusedAsNotFound,
  _MissingTenantMatchesForeignTenant, _ForeignRoleAndUserUnderOwnTenant,
  _MissingRoleAndUserMatchForeign, _TenantCallerManagesOwnTenant,
  _ListTenantsShowsOnlyOwnTenant, _CreateTenantIsPlatformOnly,
  _PlatformReachesEveryTenant, TestTenantHandlers_ForeignTenantAnswersNotFound;
  pkg/acme/api/server TestUnaryAuthorizationInterceptor_DeniesWithoutGrant
  (CreateTenantRole, UpdateTenantRole), TestAuthorizeMCPMethod_DeniesWithoutGrant
  (admin.createRole, admin.updateRole).
- Cause: two go-qrdb v0.58.2 changes, both inside go-qrdb.
  1. Admin now holds role management. go-qrdb
     pkg/permission/builtin_role_grants.go, registerAdminGrants: "Role
     management in the Admin's own tenant (ScopeSelf ...)" grants
     RolesCreate, RolesRead, RolesUpdate, RolesList, RolesAssign,
     RolesUnassign. role.BuiltInRoles projects it (pkg/role BuiltInRoles,
     Permissions: permission.RolePermissions(permission.RoleAdmin)).
     go-xkms asks for exactly roles:create / roles:update
     (pkg/acme/admin/routes.go:200,202) and the tests require 403 for "admin"
     (pkg/acme/admin/routes_authz_test.go:90,92,218; the test RBAC reads
     qrdbsdk.BuiltInRoles directly, authz_test_helpers_test.go:58-89).
     go-qrdb has RegisterRoleGrant but no way to withdraw a grant, so no
     go-xkms non-test code can take it back.
  2. The grant rule (go-qrdb#1278). go-qrdb pkg/role NewGrantGuard now wraps
     CreateRole/UpdateRole and runs ValidateGrantable, which resolves the
     caller's home roles in its own tenant (pkg/auth/rbac
     RBACAuthorizer.Authorize -> resolvePermissionSet). The admin test node
     (datastore.Open standalone, memory engine, no first boot) never seeds the
     system tenant's built-in roles, so "admin" resolves to
     "role: not found: admin" at tenant_binding_test.go:101
     (go-xkms pkg/acme/admin/tenant_service.go:1598 calls
     qrdbService.Roles().CreateRole with the caller's identity).
     v0.51.0-alpha had no grant guard, so the write went through.
- Fix: none in go-xkms (r159). Taking the principal off the context would
  bypass the grant rule, and the tests may not change. Issue text for go-qrdb:

  Title: v0.58.2-alpha: built-in Admin gains roles:create/update, and the
  grant guard fails "role: not found" on a node without first boot
  Version: github.com/jeremyhahn/go-qrdb v0.58.2-alpha
  Where: pkg/permission/builtin_role_grants.go registerAdminGrants (the
  "Role management in the Admin's own tenant" block); pkg/role NewGrantGuard
  and ValidateGrantable; pkg/auth/rbac RBACAuthorizer.resolvePermissionSet.
  Expected: (a) as in v0.51.0-alpha, Admin holds no roles:create or
  roles:update; creating and updating roles stays with the Security Officer,
  or go-qrdb offers a consumer a way to withdraw a default grant. (b) a
  CreateRole on an embedded node whose built-in roles were never seeded
  either seeds them or answers PermissionDenied, not a resolve failure.
  Actual: role.BuiltInRoles(t) gives Admin roles:create and roles:update, so
  go-xkms's admin routes answer 201/200 to "admin" where 403 is the policy;
  CreateRole by admin@system returns "qrdb/auth/rbac: failed to resolve
  permissions: role: not found: admin".
- Not fixed, fails before the merge too: TestDeviceAttestDICE* in
  pkg/acme/client.
