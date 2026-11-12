# Web console: OTA Image Keys (row 1443, lane suiz)

## Gap

Main serves `POST /api/v1/ota-image-keys/{board}` (keys:create),
`/{board}/rotate` (keys:rotate) and `/{board}/sign` (keys:sign)
(pkg/api/rest/routes.go, handlers in pkg/api/rest/handlers_ota_image.go), but
sdk/ts has no method for them and no console view calls them. Operators need
curl to provision, rotate and sign with a board's ES256 image-signing key.

## Slice

- Helper `web/app/src/lib/otaImageKeys.ts`: TS interfaces for the REST bodies
  and responses, `createOtaKey`, `rotateOtaKey`, `signOtaImage` over
  `getSDKClient().http.request`, and `hexToB64` built on `bytesToB64`.
- View `web/app/src/views/OtaImageKeysView.svelte`: `PageHeader`
  "OTA Image Keys"; board and backend inputs; Create key and Rotate key
  (confirm) buttons with busy state; result card with key ID, version and
  public key PEM with copy; Sign card with digest (64 hex) / raw base64
  toggle, Sign button and signature result; `Alert` for errors.
- Route `#/keys/ota` (`otaImageKeys`), nav entry "OTA Image Keys" in Keys &
  Crypto after TPM Policies, requires keys:create.
- One added line per place in nav.ts, two in router.svelte.ts (union, path
  map), two in App.svelte (import, dispatch); no other line changes there.
- Docs: Navigation table row in docs/web-console/user.md; changelog entry.

## Tests

`web/app/test/view3_ota_image_keys.test.ts`: create, rotate (confirm and
decline), sign digest and raw, validation (disabled buttons, bad hex, bad
base64, URL-encoded board), and error alerts on rejected create/sign.

## Checks

sdk/ts build (dist restored), svelte-auth and web/app npm ci, the new vitest
file, the whole web/app suite, svelte-check, vite build, pkg/api/rest -race,
sdk/go build, make lint.

## Out of scope

Board list route, whole-file image upload, KeysView, Go code, sdk/ts,
docs/SPEC.md.

## Results

- sdk/ts build: pass (tracked sdk/ts/dist restored after).
- svelte-auth npm ci: pass; web/app npm ci: pass.
- vitest test/view3_ota_image_keys.test.ts: pass (11 tests).
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): pass (51 files, 423 tests).
- svelte-check: pass (0 errors, 0 warnings).
- vite build (--outDir /tmp/suiz-dist): pass.
- go test -race pkg/api/rest (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues).
