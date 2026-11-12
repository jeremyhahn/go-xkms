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

Results to follow.

## Out of scope

Go code, sdk/ts, the TPM policies view, xkey, web/desktop, docs/SPEC.md.
