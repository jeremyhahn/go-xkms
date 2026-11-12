# Web console: FROST Key Import (lane suis, epic #1443 UI slice 19)

## Gap

Main serves `POST /api/v1/frost/keys/import` (keys:import) and
`GET /api/v1/frost/keys/{id}` (keys:get), and sdk/ts has `frost.importKey`
and `frost.getKey`, but FrostView only lists, generates, deletes and
verifies. A participant handed a dealer key package has no console path to
load it, and no view shows one key's participant id, threshold and group
public key.

## The view

`web/app/src/views/FrostKeyImportView.svelte`, route `#/frost/import`:

- `PageHeader` "FROST Key Import".
- A JSON textarea for the key package, checked for the required fields and
  types before the call; Import button with a busy state.
- A result card: key id, participant id, group public key.
- A lookup row (key id) with Look up and a details card: algorithm,
  "threshold of total", participant id, group public key (monospace).
- `Alert` for errors.
- The pasted text and `secret_share` live only in component state, are
  cleared after each import attempt and never reach a toast, an error or
  the console.

## Shared files

Nav entry in Keys & Crypto (`capability: "frost"`, requires keys:import).
nav.ts, router.svelte.ts and App.svelte get exactly one added line in each
of the five places (as lanes suia-suiq, suir, suit do), so merges are
trivial.

## Tests

`web/app/test/view3_frost_key_import.test.ts`: validation, import, secret
hygiene, lookup, errors. Test commit before the feat commit.

## Checks

sdk/ts build, svelte-auth install, web/app npm ci, the new vitest file, the
whole web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go
build, make lint.

## Results

Results to follow.
