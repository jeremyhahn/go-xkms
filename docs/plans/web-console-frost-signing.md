# Web console: FROST Signing view (lane suiv, epic #1443)

## Gap

Main serves POST `/api/v1/frost/keys/{id}/nonces`, POST `/api/v1/frost/keys/{id}/sign`
and POST `/api/v1/frost/aggregate` (permission keys:sign), and the TS SDK has
`frost.generateNonces`, `frost.signRound` and `frost.aggregate`. FrostView only
generates, lists, deletes and verifies keys, so a threshold signature cannot be
produced from the console.

## The view

`web/app/src/views/FrostSigningView.svelte`, titled "FROST Signing":

- key id and message inputs (the message is hex-encoded from its UTF-8 bytes);
- step 1, Generate nonces: shows participant id, session id and this node's
  commitment as JSON for sharing; the two secret nonces stay in component state
  only, never rendered, toasted or logged;
- step 2, Sign: a JSON textarea for the other participants' commitments; this
  node's commitment is added; the share is shown for sharing; the nonces are
  cleared after the round, success or failure;
- step 3, Aggregate: a JSON textarea for the other shares, a verify checkbox
  (on by default); shows the signature hex and a verified badge;
- invalid JSON shows an inline error and makes no call; API errors show an Alert.

## Wiring (one added line per place, shared rule with lanes suia-suit and suiu)

- route `#/frost/sign` -> `frostSigning` (router.svelte.ts: union + path map);
- App.svelte: import + dispatch line;
- nav.ts: one Overview entry "FROST Signing", capability `frost`, requires keys:sign.

## Tests

`web/app/test/view3_frost_signing.test.ts`: nonces, sign, aggregate, JSON
validation, secret hygiene and error Alert. Test commit precedes the feat commit.

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the whole
web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check, vite
build, pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

FrostView and its test, FrostKeyImportView, key generation/import/deletion/verify,
Go code, sdk/ts, xkey, web/desktop, docs/SPEC.md.

## Results

- sdk/ts build: pass (it rewrites the tracked sdk/ts/dist; restored, not committed).
- svelte-auth npm ci: pass. web/app npm ci: pass.
- vitest test/view3_frost_signing.test.ts: 7/7 pass.
- vitest whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage): 51 files, 419 tests pass.
- svelte-check: 2 errors, both baseline (UsersView.svelte:121 and view2_users.test.ts:51, role/roles).
- vite build: pass.
- go test -race pkg/api/rest: pass.
- sdk/go build: pass.
- make lint: pass, 0 issues.
