# Web console: Random & Hash tools (row web-console, docs/SPEC.md:139)

## Gap

Main serves POST `/api/v1/random` and POST `/api/v1/hash` (keys:verify,
pkg/api/rest/routes.go:218-219), but sdk/ts has no method for them and no
console view calls them. Operators cannot check the entropy source or the
digest paths from the console.

## Slice

- Helper `web/app/src/lib/cryptoTools.ts`: wire interfaces
  (`GenerateRandomRequest`, `GenerateRandomResponse`, `HashRequest`,
  `HashResponse`), `generateRandom(length)`, `hashData(dataB64, hash?)` over
  `getSDKClient().http.request`, and `b64ToHex` built on `b64ToBytes`.
- View `web/app/src/views/CryptoToolsView.svelte`: `PageHeader` "Random & Hash";
  a Random card (length 1-1024, Generate with busy state, hex + base64 result,
  copy button); a Hash card (textarea, "input is base64" toggle, hash select
  ""/sha256/sha384/sha512, Hash button, hex + base64 digest and algorithm);
  `Alert` for errors.
- Route `#/tools/crypto` (`cryptoTools`), nav entry "Random & Hash" in Keys &
  Crypto, requires keys:verify.
- One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2);
  no other line changes there.

## Tests

`web/app/test/view3_crypto_tools.test.ts`: random request + hex render,
length validation (0, 1025, non-integer), hash request with text and with
base64 input, default hash sends no `hash`, invalid base64 error, rejected
calls show an error Alert.

## Checks

sdk/ts build (dist restored), svelte-auth npm ci, web/app npm ci, vitest (new
file and whole suite), svelte-check, vite build, pkg/api/rest -race, sdk/go
build, make lint.

## Out of scope

HMAC, encrypt/decrypt, sign/verify, Go code, sdk/ts, docs/SPEC.md.

## Results

Results to follow.
