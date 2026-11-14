# Web console: Tenant Entitlements (epic #1443, lane suir, slice 18)

## Gap

Main serves PUT `/api/v1/tenants/{tenantID}/entitlements` (pkg/api/rest/routes.go,
permission tenants:set_entitlements, registered only when tenants are wired) and the
TS SDK has `tenants.updateEntitlements`. No console view sets entitlements:
TenantsView creates, lists and deletes tenants; Tenant Quotas (suip) sets quotas only.

## The view

`web/app/src/views/TenantEntitlementsView.svelte`, route `#/tenants/entitlements`:

- `PageHeader` "Tenant Entitlements".
- A tenant select fed by `tenants.list`; Save is disabled until a tenant is chosen.
- A note that the whole entitlement set is sent on every save.
- Four checkboxes (allow_dedicated_raft, allow_volume_storage,
  allow_system_managed_barrier, allow_dedicated_wal; unchecked sends false) and two
  comma-separated inputs (allowed_isolation_modes, allowed_barrier_modes; trimmed,
  empties dropped, an empty input sends `[]`).
- Save with a busy state; a result card with the returned `tenant.entitlements`
  ("none returned" when absent); an error `Alert` on a failed list or save.

## Nav, route, dispatch

One added line per place, at the named anchor, no other change there (the rule shared
with lanes suia-suiq and the siblings suis, suit, so merges stay trivial):

- nav.ts: after the Settings entry, `tenantEntitlements`, icon Building2,
  capability `tenants`, requires tenants:set_entitlements.
- router.svelte.ts: `| "tenantEntitlements"` after `| "login"`; the path map line
  after `"/login": "login",`.
- App.svelte: the import after the PlaceholderView import; the dispatch line after
  the login/register branch, before `{:else}`.

## Tests

`web/app/test/view3_tenant_entitlements.test.ts` (test commit before the feat commit):
load, save (payload shape), result (rendered entitlements, "none returned"), errors.

## Docs

docs/web-console/user.md Settings row of the Navigation table; changelog entry.

## Checks

sdk/ts build, svelte-auth npm ci, web/app npm ci, the new vitest file, the whole
web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check, vite build,
pkg/api/rest -race, sdk/go build, make lint.

## Results

- sdk/ts npm ci + build: pass (the build rewrites the tracked sdk/ts/dist; restored, not committed).
- sdk/ts/svelte-auth npm ci: pass. web/app npm ci: pass.
- vitest test/view3_tenant_entitlements.test.ts: 6/6 pass.
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): 51 files, 418 tests pass.
- npm run check: only the baseline errors (UsersView.svelte:121 and view2_users.test.ts:51, role/roles).
- vite build: pass.
- go test -race ./pkg/api/rest/ (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues on every module and tag set).
