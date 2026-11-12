# Web console: System Health view (lane suig, epic #1443 slice 7)

## Gap

xkmsd serves the public probes `GET /health/live`, `/health/ready`,
`/health/startup` and `GET /api/v1/algorithms` (pkg/api/rest/routes.go), and
the TS SDK exposes them on `getSDKClient().health`. The console only shows the
one-word `/health` status on the dashboard; no view calls the probes or the
algorithm list, so an operator cannot see which check holds readiness down or
which (post-quantum) algorithms the server offers.

## The view

- `SystemHealthView.svelte`, route `#/system/health` (`systemHealth`).
- `PageHeader` "System Health" with a Refresh action.
- Three probe cards (Liveness, Readiness, Startup): overall `StatusBadge`, one
  row per check (name, status, message). Probes load with `Promise.allSettled`;
  a rejected probe (e.g. 503) shows as down with its error message, never as a
  page error.
- Two algorithm tables (Signing, Key encapsulation): algorithm, curves or key
  sizes, backends, a post-quantum badge where `post_quantum` is true; an empty
  list shows an empty-state line; a failed `algorithms` call shows an `Alert`
  in that section only.
- Nav: Overview section, directly after Backends, icon `Network`, no
  `requires` (the routes are public).

## Shared files rule

Lanes suia-suif also touch nav.ts, router.svelte.ts and App.svelte. This lane
adds exactly one line in each of five places (union, path map, import,
dispatch, nav entry) and changes no other line there.

## Tests

`web/app/test/view3_system_health.test.ts` (committed before the view):
mount, probe down, algorithms tables + PQ badge + empty state, refresh,
algorithms error confined to its section.

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage),
svelte-check, vite build, pkg/api/rest -race, sdk/go build, make lint.

## Follow-ups (out of scope)

- Auto-refresh of the probes.
- A dashboard link to the System Health view.

## Results

Results to follow.
