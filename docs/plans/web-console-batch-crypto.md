# Web console: Batch Crypto (row 1443 UI slice, lane suji)

## Gap

Main serves POST `/api/v1/keys/{id}/encrypt-batch` (keys:encrypt) and
POST `/api/v1/keys/{id}/decrypt-batch` (keys:decrypt)
(pkg/api/rest/routes.go:212-213), up to 100 items per call with a result or
an error per item. sdk/ts has no method for either and no console view calls
them.

## Slice

- Helper `web/app/src/lib/keyBatch.ts`: wire interfaces, `MAX_BATCH_ITEMS = 100`,
  `encryptBatch(id, backend, items)` and `decryptBatch(id, backend, items)` over
  `getSDKClient().http.request` (key ID URL-encoded in the path).
- View `web/app/src/views/KeyBatchView.svelte`: `PageHeader` "Batch Crypto";
  key card (key ID, backend, Encrypt/Decrypt toggle); item table with
  add/remove (encrypt: plaintext text + optional additional data; decrypt:
  ciphertext, nonce, tag, additional data, key version); Run button with busy
  state; Results table (index, result fields or error) with "Copy as JSON";
  `Alert` for call errors.
- Route `#/keys/batch` (`keyBatch`), nav entry "Batch Crypto" in Keys & Crypto
  (requires keys:encrypt).
- One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2);
  no other change there.

## Tests

`web/app/test/view3_batch_crypto.test.ts`: encrypt request + per-item
result/error rendering; decrypt request + text/base64 plaintext; 100-item
limit and empty disable; key ID/backend/base64 validation; slash in key ID
URL-encoded; rejected call shows an error Alert.

## Checks

sdk/ts build (dist restored), svelte-auth + web/app npm ci, the new vitest
file, the web/app suite, svelte-check, vite build, pkg/api/rest -race,
sdk/go build, make lint. Baseline on main: view1/view2 svelte-auth tests,
svelte-check UsersView.svelte:121.

Out of scope: single-item encrypt/decrypt, rewrap, data keys, HMAC,
KeysView, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts build: pass (tracked dist restored).
- svelte-auth npm ci: pass. web/app npm ci: pass.
- vitest test/view3_batch_crypto.test.ts: pass (6 tests).
- vitest web/app suite: pass (51 files, 418 tests; no baseline failure seen).
- svelte-check: pass (0 errors, 0 warnings).
- vite build: pass.
- go test -race pkg/api/rest: pass.
- sdk/go build: pass (first try failed on missing entries in the shared /gocache, rerun with a lane-local GOCACHE).
- make lint: stopped at the 30-minute background limit during the raft tag set; every golangci-lint pass that finished reported 0 issues.
