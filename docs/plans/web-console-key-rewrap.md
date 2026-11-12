# Web console: Rewrap view (lane sujg, row web-console, docs/SPEC.md:139)

## Gap

Main serves POST `/api/v1/keys/rewrap` (keys:decrypt, pkg/api/rest/routes.go:211),
which re-encrypts a ciphertext under the source key's current version or under
another key without the plaintext leaving the server. sdk/ts has no method for
it and no console view calls it.

## Slice

- Helper `web/app/src/lib/keyRewrap.ts`: TS interfaces for `RewrapRequest`,
  `DecryptRequest` (the fields used), `EncryptResponse`, `RewrapResponse`;
  `rewrap(req)` over `getSDKClient().http.request("POST", "/api/v1/keys/rewrap", {body})`;
  `parseCiphertextInput(text)` taking a bare base64 ciphertext or a pasted
  EncryptResponse JSON object, or returning an error string.
- View `web/app/src/views/KeyRewrapView.svelte`: PageHeader "Rewrap"; Source card
  (backend, key ID, ciphertext box, nonce, tag, additional data); Target card
  (optional target backend and key ID; empty means the source key's current
  version); Rewrap button with busy state; Result card (source and new versions,
  new ciphertext/nonce/tag, "Copy as JSON"); Alert for errors.
- Route `#/keys/rewrap` (`keyRewrap`), nav entry "Rewrap" (icon Split,
  requires keys:decrypt) after TPM Policies.
- One added line per place in nav.ts, router.svelte.ts (union, path map) and
  App.svelte (import, dispatch); no other line changed there.

## Tests

`web/app/test/view3_key_rewrap.test.ts`: rewrap in place, to another key with
additional data, pasted JSON, copy as JSON, validation, error Alert.

## Checks

sdk/ts build (dist restored), svelte-auth and web/app npm ci, the new vitest
file, the whole web/app suite, svelte-check, vite build, pkg/api/rest -race,
sdk/go build, make lint.

## Results

- sdk/ts npm ci + build: pass (tracked sdk/ts/dist restored).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_key_rewrap.test.ts: pass, 8 tests.
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): pass, 51 files, 420 tests; store_nav.test.ts unchanged.
- svelte-check: pass, 0 errors (after the test reads the clipboard call with optional chaining).
- vite build to /tmp/sujg-dist: pass.
- go test -race pkg/api/rest (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass.
