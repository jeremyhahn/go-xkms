# Web console: Data Keys view (row web-console, SPEC.md:139; lane sujh, epic #1443)

## Gap

Main serves POST `/api/v1/keys/{id}/wrapped-data-key` (keys:encrypt,
pkg/api/rest/routes.go:215), but sdk/ts has no method for it and no console
view calls it. Operators setting up envelope encryption by hand need a raw API
call to mint a wrapped data key. The sibling `/keys/{id}/data-key` returns the
plaintext key and stays out of the browser on purpose.

## Slice

- Helper `web/app/src/lib/wrappedDataKey.ts`: TS interfaces for the wire types
  (`GenerateWrappedDataKeyRequest`, `EncryptResponse`,
  `GenerateWrappedDataKeyResponse`) and `generateWrappedDataKey(id, backend,
  keySize?, aadB64?)` over `getSDKClient().http.request`. No function for the
  plaintext data-key route.
- View `web/app/src/views/WrappedDataKeyView.svelte`: PageHeader "Data Keys"
  (the key is returned only wrapped; the service unwraps it with a decrypt
  call), an input card (key ID, backend, key size 32/24/16, optional
  additional data), Generate with a busy state, a Result card (ciphertext,
  nonce, tag, iv, key version, "Copy as JSON"), an error Alert.
- Route `#/keys/data-keys` -> `wrappedDataKey`; nav entry "Data Keys" in Keys &
  Crypto after TPM Policies, requires keys:encrypt.
- One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2);
  no other line changed there.

## Tests

`web/app/test/view3_wrapped_data_key.test.ts`: generate (path, body, rendered
fields), options (key_size 16, additional_data base64, URL-encoded ID), never
plaintext (no call to a path ending in `/data-key`), copy (clipboard + toast),
validation (Generate disabled), errors (Alert with the message).

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the whole
web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build,
make lint. Baseline on main: view1/view2 svelte-auth tests,
UsersView.svelte:121 svelte-check error.

## Out of scope

`/keys/{id}/data-key`, rewrap (sujg), encrypt/decrypt/batch, HMAC (suje),
KeysView, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts npm ci + build: pass (tracked sdk/ts/dist restored after).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_wrapped_data_key.test.ts: pass (5 tests).
- vitest whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage): pass (51 files, 417 tests).
- svelte-check: pass (0 errors, 0 warnings).
- vite build to /tmp/sujh-dist: pass.
- go test -race pkg/api/rest (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues on every module and tag set).
- nav.ts +1, router.svelte.ts +2, App.svelte +2 lines against main, none removed.
