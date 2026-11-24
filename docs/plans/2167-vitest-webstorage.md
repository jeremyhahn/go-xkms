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

Node v26.10.0, NODE_OPTIONS unset, `npm ci --silent` per package.

| Package | New test before fix | After fix | Suite after fix |
|---|---|---|---|
| sdk/ts/svelte-auth (vitest ^2) | FAIL (localStorage undefined) | pass | test:coverage 112/112, thresholds met |
| web/app (vitest ^2) | FAIL | pass | test:coverage 413/413 (51 files), thresholds met |
| xkey/frontend (vitest ^1.6) | FAIL | pass | npm test 89/89 (11 files) |

xkey/frontend's default pool accepted the execArgv; no `pool: 'forks'` needed.
Before the fix the brief records 90/111 svelte-auth tests failing at
`window.localStorage.clear()`.

CI at d47d4d24 failed `make test-web` in the devcontainer image: its Node
v20.20.2 (scripts/tool-pins.sh `NODE_VERSION`) printed `bad option:
--no-experimental-webstorage` and every svelte-auth vitest worker exited
(web/app and xkey/frontend would fail the same way). The flag exists only
from Node 22.4, and Node 20 has no global localStorage, so jsdom's storage
is already the one tests see there. Each config now builds `webstorageOff`
from `process.allowedNodeEnvironmentFlags.has('--experimental-webstorage')`
and passes the flag only when the running Node knows it;
internal/buildgates/vitest_webstorage_test.go fails on a literal execArgv
while the pinned Node is older than 22.4. Re-measured under Node v26.10.0,
NODE_OPTIONS unset, `make test-web`: sdk/ts 196/196, svelte-auth 112/112,
web/app 413/413 (51 files, svelte-check 0/0), xkey/frontend 89/89; Node 20
not run locally (the buildgates test is the guard).
