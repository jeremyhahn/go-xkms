# Web console: Signing Keys view (epic #1697, slice 1)

## Gap

docs/SPEC.md:121 lets a tenant name a signing key per repository; the release
key signs every repository it has not named. Main has the REST verbs
(`/api/v1/attestation/signing-keys`, `.../binding`, `.../resolve`) and the TS
SDK client `getSDKClient().signingKeys`, but the web console has no screen, so
a binding can be set only through xkmsctl or the raw API.

## The view

- `web/app/src/views/SigningKeysView.svelte`: `PageHeader` "Signing Keys"; a
  bindings table (repository, key id, backend, updated) with an empty state
  saying the release key signs every repository; a "Set binding" modal form
  (repository, key id, optional backend); a confirm modal for delete; a resolve
  form that shows the bound key or that the release key signs; an `Alert` on a
  load error.
- Route `signingKeys`, path `#/attestation/signing-keys` (router.svelte.ts,
  App.svelte dispatch).
- Nav: Security entry "Signing Keys" after OIDC Credentials, icon `KeyRound`,
  requires `attestation_signing_keys:list`.

## Tests

`web/app/test/view3_signing_keys.test.ts` (test commit before the feat
commit): list on mount and empty state; set (arguments, no `backend` when
empty, submit disabled until repository and key id are filled); delete with
confirm and cancel; resolve with `default` true and false; list and set errors.

## Checks

sdk/ts build, web/app npm ci, the new vitest file, the web/app suite,
svelte-check, vite build, `go test -race ./pkg/api/rest/`, sdk/go build,
make lint. Results (2026-11-12, Node v26.10.0):

- sdk/ts `npm ci && npm run build`: pass (dist/ is tracked; restored, not committed).
- web/app `npm ci`: pass.
- `npx vitest run test/view3_signing_keys.test.ts`: pass, 11 tests.
- `npm test`: the new file and store_nav pass; 10 failures outside this slice:
  test/theme.test.ts and test/store_theme_extra.test.ts (`localStorage`
  undefined under Node 26), test/view1_login.test.ts and
  test/view2_register.test.ts (sdk/ts/svelte-auth dependency setup).
- `npm run check`: 2 errors, both already on main: src/views/UsersView.svelte:121
  and test/view2_users.test.ts:51 (`role` vs `roles` on `UserInfo`).
- `npx vite build`: pass.
- `go test -race ./pkg/api/rest/` (codec tags): pass.
- sdk/go `go build ./...`: pass.
- `make lint`: pass, 0 issues.

## Out of scope / follow-up

- A `signing_keys` server capability flag so the nav entry can hide on servers
  without the verbs; the capability map lives in Go, so it is a later slice.
- Go code, sdk/ts, xkey, web/desktop, docs/SPEC.md.
