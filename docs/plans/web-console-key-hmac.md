# Web console: HMAC view (row web-console, docs/SPEC.md:139; lane suje)

## Gap

Main serves POST `/api/v1/keys/{id}/hmac` (keys:sign) and
POST `/api/v1/keys/{id}/hmac/verify` (keys:verify)
(pkg/api/rest/routes.go:216-217), but sdk/ts has no method for them and no
console view calls them.

## Slice

- Helper `web/app/src/lib/keyHmac.ts`: wire interfaces
  (GenerateHMACRequest/Response, VerifyHMACRequest/Response),
  `computeHmac`, `verifyHmac` over `getSDKClient().http.request`, and
  `b64ToHex` / `macToB64` on the b64.ts helpers.
- View `web/app/src/views/KeyHmacView.svelte`: PageHeader "HMAC"; key ID and
  backend inputs; data textarea with a base64 toggle and a hash select
  (server default, sha256, sha384, sha512); a Compute card (MAC as hex and
  base64, copy button); a Verify card (MAC input, hex or base64, StatusBadge
  valid/invalid); busy buttons; error Alert.
- Route `#/keys/hmac` -> `keyHmac`; nav entry "HMAC" in Keys & Crypto,
  requires keys:sign.
- One added line per place in nav.ts, two in router.svelte.ts (union, path
  map), two in App.svelte (import, dispatch); no other line changed there.
- Tests: web/app/test/view3_key_hmac.test.ts (compute, verify, validation,
  errors), committed before the code (ruling 286).
- Docs: docs/web-console/user.md Navigation row; changelog entry.

## Checks

sdk/ts build (dist restored), svelte-auth npm ci, web/app npm ci, the new
vitest file, the whole vitest suite, npm run check, vite build,
pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

Keyless hashing, encrypt/decrypt, sign/verify, data keys, KeysView, Go code,
sdk/ts, docs/SPEC.md.

## Results

- sdk/ts npm ci + build: pass (tracked sdk/ts/dist restored).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_key_hmac.test.ts: pass (10 tests).
- vitest whole web/app suite: pass (51 files, 422 tests; the view1/view2 svelte-auth baseline tests pass with svelte-auth installed).
- npm run check (svelte-check): pass, 0 errors (the UsersView.svelte:121 baseline did not show).
- vite build: pass.
- go test -race pkg/api/rest: pass.
- sdk/go go build ./...: pass.
- make lint: pass.
