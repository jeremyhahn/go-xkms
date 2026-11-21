# Web console: Public Keys view (epic #1443, row web-console, docs/SPEC.md:139)

## Gap

Main serves GET `/api/v1/keys/{id}/public-key` (keys:get, pkg/api/rest/routes.go:222),
but sdk/ts has no method for it and no console view calls it. Operators fetch the
public half with a raw API call and convert DER to PEM by hand.

## Plan

- Helper `web/app/src/lib/keyPublicKey.ts`: the `GetPublicKeyResponse` interface
  (key_id, public_key as base64 DER, algorithm?, version, timestamp), a pure
  `toPem(b64)` (64-character lines between BEGIN/END PUBLIC KEY) and
  `getPublicKey(id, backend, version?)` over `getSDKClient().http.request`.
- View `web/app/src/views/KeyPublicKeyView.svelte`: PageHeader "Public Keys"
  (only the public half is ever returned), inputs for key ID, backend and an
  optional positive-integer version, a Fetch button with a busy state, a Result
  card (key ID, algorithm, version, timestamp, base64 and PEM in monospace,
  "Copy PEM", "Download .pem" as `<key_id>-v<version>.pem`), an error Alert.
- Route `#/keys/public-key` -> `keyPublicKey`; nav entry "Public Keys" in Keys &
  Crypto after TPM Policies, gated on keys:get.
- One-line-per-place rule: nav.ts one added line, router.svelte.ts two, App.svelte
  two; no other line changed there.
- Tests: `web/app/test/view3_key_public_key.test.ts` (fetch, pem, version,
  copy, encoding, errors), committed before the feature (ruling 286).
- Docs: Navigation table row in docs/web-console/user.md; changelog entry.

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the web/app
suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

Private-key export, key versions listing, certificates, KeysView.svelte, Go code,
sdk/ts, docs/SPEC.md.

## Results

Results to follow.
