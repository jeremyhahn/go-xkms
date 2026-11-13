# Web console: Seal view (epic #1443, UI slice 2)

## Gap

The server serves `POST /api/v1/seal` (keys:encrypt), `POST /api/v1/unseal`
(keys:decrypt) and `GET /api/v1/seal/capability?backend=` (keys:get), and
sdk/ts exposes them as `getSDKClient().seal`. No console view calls them: a
TPM2 seal bound to a TPM policy is reachable only through xkmsctl or the raw
API.

## The view (web/app/src/views/SealView.svelte)

- `PageHeader` titled "Seal".
- Seal form: backend select (from `backends.list`), capability check on each
  backend choice (`seal.capability(id)`; `can_seal: false` shows a line and
  disables Seal), optional key id, text to seal, optional aad, password and
  TPM policy. Empty optional fields are left out of the request.
- Result block: the full `SealResponse` as JSON with a copy button.
- Unseal form: paste the seal result JSON; backend, ciphertext, nonce, tag,
  metadata, key_id and key_version are copied into `seal.unseal`; the
  plaintext is shown as text. Invalid JSON or non-base64 ciphertext shows an
  inline error and calls nothing.

## Route and nav

- Route `#/seal` (`RouteName` `"seal"`).
- Nav entry in Keys & Crypto after TPM Policies, icon `Lock`, requires
  `keys:encrypt`.
- One-line-per-place rule (shared with lane suia, Signing Keys): exactly one
  added line in each of the RouteName union, the path map, the App.svelte
  imports, the App.svelte dispatch and nav.ts; no other line changes there.

## Tests (web/app/test/view3_seal.test.ts)

mount + capability, seal request shape and result JSON, unseal from the JSON
plus the inline errors, error toast on a rejected seal, error alert on a
rejected backend list.

## Checks

sdk/ts build, web/app npm ci, the new vitest file, the whole web/app suite,
svelte-check, vite build, pkg/api/rest -race, sdk/go build, make lint.

## Results

- sdk/ts `npm ci && npm run build`: pass (rewrites the tracked sdk/ts/dist; restored, not committed).
- web/app `npm ci`: pass.
- `npx vitest run test/view3_seal.test.ts`: pass, 6 tests.
- `npm test`: 404 pass, 5 fail outside this slice: test/store_theme_extra.test.ts:43 and test/theme.test.ts:30 (`localStorage` undefined: Node 26's global localStorage shadows jsdom), test/view1_login.test.ts and test/view2_register.test.ts (fail to load until sdk/ts/svelte-auth has its own `npm ci`, then fail on the same localStorage cause).
- `npm run check`: pass against the committed sdk/ts dist (with a fresh sdk/ts build: 2 errors in UsersView.svelte:121 and view2_users.test.ts:51, `role` vs `roles`, outside this slice).
- `npx vite build`: pass.
- `go test -race ./pkg/api/rest/` (codec tags): pass.
- `cd sdk/go && go build ./...`: pass.
- `make lint`: pass, 0 issues.
- Note: the feat commit carries the test commit's subject line by mistake (stale message file); no amend under the lane rules.

## Out of scope

Go code, sdk/ts, the TPM policies view, xkey, web/desktop, docs/SPEC.md.
