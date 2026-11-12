# Web console: Platform Secret Names (epic #1443, lane suit)

## Gap

The REST API serves `GET /api/v1/platform/secrets` (permission keys:list,
registered only when the platform seal store is wired) and the TS SDK has
`platform.listSecrets`, but no console view lists the names. PlatformView can
put, delete and reseal a secret only by a name the operator already knows.

## The view

- `PlatformSecretNamesView.svelte`: `PageHeader` "Secret Names" with a
  Refresh button, a filter input (case-insensitive substring, client side),
  the total, the names sorted in monospace, an empty state
  ("No secrets stored") and an error `Alert`.
- Only names are shown: `platform.getSecret` is never called.
- Route `#/platform/secrets` (`platformSecretNames`).
- Nav entry "Secret Names" in the Settings section, `capability: "platform"`,
  `requires: keys:list`.

## Shared files

nav.ts, router.svelte.ts and App.svelte are touched by lanes suia-suiq and
suir, suis too: this lane adds exactly one line per place (nav entry, union
member, path map entry, import, dispatch) and changes no other line.

## Tests

`web/app/test/view3_platform_secret_names.test.ts`: load (sorted names and
total), filter (no extra call), empty, refresh (second call, no getSecret),
error Alert.

## Checks

sdk/ts build, svelte-auth npm ci, web/app npm ci, the new vitest file, the
whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage), npm run
check, vite build, `go test -race ./pkg/api/rest/`, sdk/go build, make lint.

## Results

Results to follow.
