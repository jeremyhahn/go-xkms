# #2167: vitest jsdom localStorage under Node 26

## Cause

Node 26 enables the Web Storage API by default. Its global `localStorage`
shadows the one jsdom installs, so under vitest's jsdom environment
`window.localStorage` is undefined (no `--localstorage-file` given) and
tests fail at `window.localStorage.clear()` (svelte-auth
test/LoginPanel.test.ts:69, RegisterPanel.test.ts:69).

## Method

Fix the test harness, not the image: the vitest worker processes run with
`--no-experimental-webstorage`, so jsdom's storage is the only one. The fix
must work with `NODE_OPTIONS` unset (the go-xkms.env stopgap is removed
when this merges).

Versions: sdk/ts/svelte-auth and web/app use vitest ^2, xkey/frontend
vitest ^1.6. Both accept `poolOptions.{forks,threads}.execArgv`.

## Slices

1. Test commit: one jsdom test per package (svelte-auth, web/app,
   xkey/frontend) asserting `window.localStorage.clear` is a function and a
   setItem/getItem round-trip. Fails before the fix with NODE_OPTIONS unset.
2. Fix commit: `poolOptions` execArgv in each vitest config's `test`
   block; coverage thresholds unchanged; changelog entry.
3. Checks: `npm run test:coverage` per package, `make lint`; results below.

## Out of scope

The CI image, package.json and lock files, NODE_OPTIONS in go-xkms.env.

## Results
