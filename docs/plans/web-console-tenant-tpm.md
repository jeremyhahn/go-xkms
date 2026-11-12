# Web console: Tenant TPM view (epic #1443, lane suie)

## Gap

The REST verbs under `/api/v1/tenants/{tenantID}/tpm` (GET/PUT mode, GET
vtpm status, POST vtpm start/stop; capability `tpm_policies`) and the TS SDK
methods on `getSDKClient().tenants` exist, but no console view calls them.
An operator needs `xkmsctl tenant tpm-mode` to see or set a tenant's TPM
mode or to manage its vTPM.

## The view (web/app/src/views/TenantTpmView.svelte)

- `PageHeader` "Tenant TPM"; a tenant select filled from `tenants.list()`
  (`name (id)`, or `id` when the name is empty).
- Mode panel: current mode from `getTPMMode(id)`; a none/shared/vtpm select,
  an optional owner-auth field and Apply. Apply opens a confirm `Modal`
  stating the change is refused while the tenant holds TPM keys or policies;
  confirm calls `setTPMMode(id, {tenant_id, mode[, owner_auth]})`.
- vTPM panel (mode "vtpm" only): `vtpmStatus(id)` shown with a `StatusBadge`
  (running, pid, socket, restarts); Start when stopped, Stop (with confirm)
  when running.
- `Alert` on a list or mode load error; error toasts on action failures.

## Wiring

- Route `#/tenants/tpm` -> `tenantTpm`; nav entry "Tenant TPM" (icon Server)
  directly after Tenants in Identity & Access, capability `tpm_policies`,
  requires `tenants:read`.
- One added line in each of the five shared places (RouteName union, path
  map, App.svelte import, App.svelte dispatch, nav.ts), no other change
  there, so merges with lanes suia-suid stay trivial.

## Tests

web/app/test/view3_tenant_tpm.test.ts: mount and select, set mode (confirm,
cancel, owner_auth, rejection), vTPM start/stop, list and mode load errors.

## Checks

sdk/ts build, web/app npm ci, the new vitest file, npm test, npm run check,
vite build, pkg/api/rest -race, sdk/go build, make lint. Results:

- sdk/ts npm ci + build: pass (rewrites tracked sdk/ts/dist; restored, not committed).
- web/app npm ci: pass.
- vitest test/view3_tenant_tpm.test.ts: 11/11 pass.
- npm test: 409 pass, 5 fail + 2 suites, all baseline (theme localStorage under Node 26; view1_login/view2_register svelte-auth import).
- npm run check: 8 errors, all baseline (sdk/ts/svelte-auth module resolution; UsersView.svelte:121 role/roles and its test); none in this slice.
- vite build: fails on main's baseline (svelte-auth cannot resolve @go-xkms/sdk) until sdk/ts/svelte-auth has npm ci; with it, pass.
- go test -race ./pkg/api/rest/: pass.
- sdk/go go build ./...: pass.
- make lint: pass.

## Follow-up

A link from TenantsView to this view (out of scope here).
