# Web console: Tenant Quotas view (epic #1443, lane suip)

## Gap

The server takes a tenant's quotas in one call, PUT
`/api/v1/tenants/{tenantID}/quotas` (permission `tenants:set_quotas`,
registered only when tenants are wired), and the TS SDK has
`tenants.updateQuotas`. TenantsView creates, lists and deletes tenants but
never sets quotas, so no console view makes the call or shows the stored
quotas the reply carries.

## The view

- `web/app/src/views/TenantQuotasView.svelte`: `PageHeader` "Tenant Quotas";
  a tenant select fed by `tenants.list`; a note that the whole quota set is
  sent and an empty field means 0; 16 integer inputs, one per `TenantQuotas`
  field, labelled by field name; Save with a busy state, disabled until a
  tenant is chosen; inline errors for negative or non-integer values; a result
  card with the returned `tenant.quotas` ("none returned" when absent); an
  error `Alert` when `list` or `updateQuotas` rejects.
- Route `#/tenants/quotas` (route name `tenantQuotas`).
- Nav entry "Tenant Quotas" in Identity & Access, `capability: "tenants"`,
  `requires: tenants:set_quotas`.

## One line per place

Lanes suia-suio and suiq also touch nav.ts, router.svelte.ts and App.svelte.
This lane adds exactly one line in each of five places (nav item; RouteName
union; path map; App import; App dispatch) at the named anchors and changes no
other line there, so merges stay trivial.

## Slices

1. test(web): `web/app/test/view3_tenant_quotas.test.ts` - load, save (all 16
   fields, unset = 0), result rendering, validation, errors. Fails until 2.
2. feat(web): the view, route, nav entry, App dispatch.
3. docs(web-console): user.md Navigation row; changelog entry.

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check,
vite build, `go test -race ./pkg/api/rest/` with the codec tags, sdk/go build,
make lint. Baseline on main, not fixed here: view1/view2 svelte-auth tests,
svelte-check at UsersView.svelte:121.

## Out of scope

TenantsView and its test, TenantTpmView, entitlements, tenant create/delete,
Go code, sdk/ts, xkey, web/desktop, docs/SPEC.md.

## Results

- sdk/ts build: pass (tracked sdk/ts/dist restored after the build, not committed).
- svelte-auth npm ci: pass. web/app npm ci: pass.
- vitest test/view3_tenant_quotas.test.ts: pass (8 tests).
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): pass (51 files, 420 tests).
- svelte-check: baseline only (UsersView.svelte:121 role/roles and test/view2_users.test.ts:51, same cause).
- vite build: pass.
- go test -race pkg/api/rest with the codec tags: pass.
- sdk/go build: pass.
- make lint: pass.
