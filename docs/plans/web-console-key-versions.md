# Web console: Key Versions view (epic #1443, UI slice 3)

## Gap

Rotating a key creates its next version as its own backend key. The REST API
(`GET /api/v1/keys/{id}/versions`, `POST .../versions/{n}/enable|disable|retire`,
`POST .../versions/enable-all|disable-all`, `POST /api/v1/keys/rotate-all`) and the
TS SDK (`getSDKClient().keys.versions`, `KeyVersionsClient`) cover versions, but
no console view calls them: an operator cannot see, enable, disable or retire an
old version, or rotate a tenant's keys, without xkmsctl. Key versions bind to the
same TPM policy as their key (docs/tpm-policies, "Key versions").

## The view

`web/app/src/views/KeyVersionsView.svelte`, route `#/keys/versions`:

- `PageHeader` "Key Versions" with a "Rotate all keys" action.
- A key select filled from `keys.list()`, labelled `key_id (backend)`.
- The versions table: version, state, created time, a "current" badge; row
  actions Enable (disabled versions), Disable and Retire (non-current versions).
- Bulk actions Enable all / Disable all, toasting the count.
- A confirm `Modal` for Retire (names the version, says the key material is
  deleted) and for Rotate all (shows rotated/skipped/failed and each failure).
- An `Alert` when loading the versions fails.

## Shared files

Lanes suia (Signing Keys) and suib (Seal) also touch nav.ts, router.svelte.ts and
App.svelte. This lane adds exactly one line in each of five places and changes no
other line: the `RouteName` union, the path map, the App import, the App
dispatch, and the nav entry directly after Keys (requires `keys:list`).

## Tests

`web/app/test/view3_key_versions.test.ts` (test commit before the feat commit):
mount and list, row actions, retire confirm/cancel, bulk actions, rotate all,
load and retire errors.

## Checks

sdk/ts build, web/app npm ci, the new vitest file, the whole web/app suite,
svelte-check, vite build, `pkg/api/rest` -race, sdk/go build, make lint.

Results (2026-11-12, Node 26.10.0):

- sdk/ts `npm ci && npm run build`: pass (dist/ rebuilt locally, restored, not committed).
- web/app `npm ci`: pass.
- `npx vitest run test/view3_key_versions.test.ts`: pass, 10 tests.
- web/app `npm test`: pass only with `NODE_OPTIONS=--no-experimental-webstorage` (422 tests). Without
  it, Node 26's built-in `localStorage` shadows jsdom's: store_theme_extra, theme, view1_login and
  view2_register fail (`Cannot read properties of undefined (reading 'clear')`). Those tests do not
  touch this slice; it is a container Node version issue.
- web/app `npm run check`: 2 errors, both on main and not in this slice:
  src/views/UsersView.svelte:121 and test/view2_users.test.ts:51 (`role` vs `roles` on UserInfo).
  It also needs `npm ci` in sdk/ts/svelte-auth first (otherwise svelte-auth cannot resolve
  `@go-xkms/sdk` and the vite build fails too).
- `npx vite build`: pass (after the svelte-auth `npm ci`).
- `go test -race ./pkg/api/rest/` (codec tags): pass.
- sdk/go `go build ./...`: pass.
- `make lint`: pass.

## Follow-up

A link from KeysView to the key's versions (out of scope here).
