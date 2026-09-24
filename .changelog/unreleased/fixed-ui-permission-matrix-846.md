- **The web console's Auth Factors and Audit sidebar entries, plus several
  key/user action buttons, now appear for identities holding the grant.**
  `web/app/src/lib/nav.ts` gates the Auth Factors entry on `{users, read}`
  and Audit on `{audit, read}`, and several `can()` checks in
  `KeyDetail.svelte`, `UsersView.svelte`, `FrostView.svelte`, and
  `BarrierView.svelte` gate on `keys:verify`, `keys:decrypt`, `keys:wrap`,
  `keys:derive`, `keys:rotate`, `users:update`, `users:delete`, and
  `seal:seal` — none of which `uiPermissionMatrix`
  (`pkg/api/rest/handlers_auth.go`) reported, so `GET /api/v1/auth/me` never
  returned those keys and `can()` (`web/app/src/stores/session.svelte.ts`)
  was permanently false for them regardless of the caller's actual RBAC
  grant. `uiPermissionMatrix` now carries all ten missing pairs. A new Go
  test, `TestUIPermissionMatrix_CoversNavRequires`
  (`pkg/api/rest/handlers_auth_navmatrix_test.go`), extracts every
  `requires: { resource, action }` gate from `nav.ts` by regex and fails if
  `uiPermissionMatrix` is missing one, so this class of drift fails CI
  instead of shipping silently; `TestAuthMe_PermissionsReflectRBACGrant` and
  `TestAuthMe_PermissionsDenyWithoutRBACGrant`
  (`pkg/api/rest/handlers_auth_test.go`) cover the `/auth/me` response for an
  identity with and without the `audit:read` grant. Fixes go-xkms#846.
