# Web console: Key Safety view (epic #1443, lane suix, slice 24)

## Gap

The server serves the key usage-limit routes, but no console view calls them
and sdk/ts has no method for them:

- PUT `/api/v1/keys/{id}/safety` (keys:rotate): set limits
- DELETE `/api/v1/keys/{id}/safety?backend=` (keys:rotate): clear limits
- GET `/api/v1/safety/check` (keys:get): keys near or past their limits
- GET `/api/v1/safety/report` (keys:get): usage report

An operator cannot see which keys are near their limits, nor set or clear a
limit, from the console.

## Plan

- `web/app/src/lib/keySafety.ts`: wire-type interfaces and `safetyCheck()`,
  `safetyReport()`, `setKeySafety(req)`, `clearKeySafety(keyId, backend)` over
  `getSDKClient().http.request`. No sdk/ts change, no new REST route.
- `web/app/src/views/KeySafetyView.svelte`: `PageHeader` "Key Safety"; report
  totals card; warnings table (`StatusBadge` for status); report table of all
  items; limits form (key ID, backend, max operations, max bytes, warning
  percent) with Set limits and Clear limits (confirm), busy state, inline
  validation, `Alert` for errors.
- Route `#/keys/safety` (`keySafety`), nav entry "Key Safety" in Keys & Crypto,
  gated on keys:get.
- One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2);
  no other line changed there.

## Tests

`web/app/test/view3_key_safety.test.ts` (committed before the view):
load, set, clear (confirm and decline), validation, errors.

## Checks

sdk/ts build (dist restored), svelte-auth install, web/app npm ci, vitest
(new file and full suite), svelte-check, vite build, pkg/api/rest -race,
sdk/go build, make lint.

## Out of scope

KeysView, key versions, Go code, sdk/ts, docs/SPEC.md.

## Results

Results to follow.
