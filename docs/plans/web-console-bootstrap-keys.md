# Web console: Bootstrap Keys view (lane sujf, epic #1443)

## Gap

Main serves GET `/api/v1/bootstrap/keys` (bootstrap:read; pkg/api/rest/routes.go:295,
handler pkg/api/rest/handlers_bootstrap.go:51-72, 503 when the listener is off), but
sdk/ts has no method for it and no console view calls it. Administrators copy the
listener's static keys into first-contact clients by raw API call today.

## Slice

- Helper `web/app/src/lib/bootstrapKeys.ts`: `BootstrapListenerKeysResponse`
  (`noise_public_key?`, `p256_public_key?`), `getBootstrapKeys()` over
  `getSDKClient().http.request`, `isListenerDisabled(err)` (XkmsApiError 503/404).
- View `web/app/src/views/BootstrapKeysView.svelte`: PageHeader "Bootstrap Keys" with
  Refresh; one card per key (label, hex in monospace, copy button, the client setting
  that takes it); info Alert for a disabled listener; error Alert; loading state.
- Route `#/bootstrap/keys` (`bootstrapKeys`), nav entry "Bootstrap Keys" in Security,
  gated on bootstrap:read.
- One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2); no other
  line changed there.

## Tests

`web/app/test/view3_bootstrap_keys.test.ts`: load, one key, copy, not enabled
(503 and 404), errors (500), refresh. Committed before the feature (ruling 286).

## Checks

sdk/ts build (dist restored), svelte-auth npm ci, web/app npm ci, the new vitest file,
the web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

`/v1/ca/bootstrap`, Trust Roots view (suiw), any key write, Go code, sdk/ts, SPEC.md.

## Results

Results to follow.
