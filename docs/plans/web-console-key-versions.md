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

Results to follow.

## Follow-up

A link from KeysView to the key's versions (out of scope here).
