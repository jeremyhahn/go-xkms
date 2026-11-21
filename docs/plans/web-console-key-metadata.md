# Web console: Key Metadata view (lane sujc, row web-console, SPEC.md:139)

## Gap

Main serves GET and PUT `/api/v1/keys/{id}/metadata` (keys:get, keys:rotate;
pkg/api/rest/routes.go:225-226), but sdk/ts has no method for them and no
console view calls them. Operators cannot see or change a key's name,
description or tags from the console.

## Slice

- Helper `web/app/src/lib/keyMetadata.ts`: wire interfaces (`KeyMetadata`,
  `KeyMetadataResponse`, `UpdateKeyMetadataRequest`), `getKeyMetadata(id,
  backend)`, `updateKeyMetadata(id, backend, changes)` over
  `getSDKClient().http.request`, and a pure `diffMetadata(before, after)` that
  builds the PUT body (changed name/description, added or changed tags,
  `remove_tags` for deleted ones).
- View `web/app/src/views/KeyMetadataView.svelte`: `PageHeader` "Key
  Metadata"; key ID and backend inputs with Load; read-only card (status,
  algorithm, usage, version, flags, dates, owner, rotation policy summary);
  edit form (name, description, tag table with add/edit/delete); Save with
  busy state; `Alert` for errors; inline tag validation (empty, duplicate).
- Route `#/keys/metadata` (`keyMetadata`), nav entry "Key Metadata" in
  Keys & Crypto, requires keys:get.
- One added line per place in nav.ts (1), router.svelte.ts (2), App.svelte (2);
  no other line changed there.

## Tests

`web/app/test/view3_key_metadata.test.ts`: load, save (diff body), no-op
(Save disabled), validation (Load disabled; empty/duplicate tag key), errors
(rejected GET/PUT show an Alert).

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the whole
web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build,
make lint.

## Out of scope

Access policy (suja), rotation policy edits (sujb; shown read-only), key
versions, KeysView, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts npm ci + build: pass (tracked sdk/ts/dist restored afterwards).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_key_metadata.test.ts: pass, 9 tests.
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): pass, 51 files, 421 tests.
- svelte-check: pass, 0 errors, 0 warnings.
- vite build to /tmp: pass.
- go test -race pkg/api/rest (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass, 0 issues.
- Departure from the brief: diffMetadata omits an emptied name or description,
  because the server reads an empty value as "unchanged".
