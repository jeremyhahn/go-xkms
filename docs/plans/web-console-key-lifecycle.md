# Web console: Key Lifecycle view (epic #1443, lane sujk)

## Gap

Main serves POST `/api/v1/keys/{id}/status` (keys:rotate) and POST
`/api/v1/keys/{id}/revoke` (keys:delete), but no console view calls either.
Operators disabling a suspect key version or revoking a retired key need a
raw API call.

## Slice

- Helper `web/app/src/lib/keyLifecycle.ts`: wire interfaces and
  `setKeyStatus(id, backend, status, version?)`, `revokeKey(id, backend, reason?)`
  over `getSDKClient().http.request`; the key ID is URL-encoded in the path.
- View `web/app/src/views/KeyLifecycleView.svelte`: `PageHeader` "Key Lifecycle"
  (revoke cannot be undone); key card (key ID, backend, optional version,
  Enable/Disable with busy state); destructive Revoke card (reason, typed
  confirmation that must equal the key ID); Result line (key ID, version,
  status, timestamp); `Alert` for errors. Only enabled/disabled are settable.
- Route `#/keys/lifecycle` (`keyLifecycle`); nav entry "Key Lifecycle" in
  Keys & Crypto, requires keys:rotate.
- One added line per place in nav.ts, two in router.svelte.ts (union, path
  map), two in App.svelte (import, dispatch); no other line changes there.

## Tests (web/app/test/view3_key_lifecycle.test.ts)

disable (no version), version 3 enable and 0/-1 blocking, revoke behind the
typed confirmation, no status other than enabled/disabled, slash in the key
ID URL-encoded in both paths, error Alert on a rejected call.

## Checks

sdk/ts build (dist restored), svelte-auth and web/app npm ci, the new vitest
file, the whole web/app suite, svelte-check, vite build, pkg/api/rest -race,
sdk/go build, make lint.

## Out of scope

Deletion, rotation and rotation policy, version listing, other statuses as
user choices, KeysView, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts build: pass (tracked dist restored).
- svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_key_lifecycle.test.ts: pass (6 tests).
- vitest whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage): pass (51 files, 418 tests).
- svelte-check: pass (0 errors, 0 warnings).
- vite build: pass.
- go test -race pkg/api/rest: pass.
- sdk/go build: pass.
- make lint: pass (0 issues on every module and tag set).
