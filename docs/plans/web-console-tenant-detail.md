# Web console: Tenant Detail (row 1443, slice 39, lane sujm)

## Gap

Main serves GET and DELETE `/api/v1/tenants/{tenantID}` (pkg/api/rest/routes.go:368-369)
and sdk/ts has `tenants.get` and `tenants.delete`, but no console view calls
either. Removing a tenant needs a raw API call today.

## Plan

- Helper `web/app/src/lib/tenantDetail.ts`: `listTenantIds`, `loadTenant`,
  `deleteTenant` over `getSDKClient().tenants`, and `isNotFound` (status 404).
- View `web/app/src/views/TenantDetailView.svelte`: PageHeader "Tenant Detail";
  a card with a tenant select (from `list()`), a free ID input (wins when set)
  and Load; a details card (ID, name, sealed, isolation type, created, updated);
  a destructive Delete card whose button is enabled only when the typed
  confirmation equals the loaded tenant's ID; `Alert` for errors, "Tenant not
  found" on 404 (never says the tenant exists).
- Route `#/tenants/detail` -> `tenantDetail`; nav entry "Tenant Detail" after
  Tenants (tenants:read, tenants capability).
- One added line per place in nav.ts, two in router.svelte.ts, two in
  App.svelte; no other line changed there.
- Tests: web/app/test/view3_tenant_detail.test.ts (list, load, id input,
  delete gate + refresh, not found, errors), committed before the feature.
- Docs: Navigation table row in docs/web-console/user.md; changelog entry.

## Out of scope

Tenant create/list (TenantsView), entitlements, quotas, TPM, status, seal,
Go code, sdk/ts, docs/SPEC.md.

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the web/app
suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build, make lint.

## Results

Results to follow.
