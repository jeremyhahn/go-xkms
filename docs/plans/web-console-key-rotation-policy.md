# Web console: key Rotation Policy view (epic #1443, lane sujb)

## Gap

Main serves GET, PUT and DELETE `/api/v1/keys/{id}/rotation-policy`
(pkg/api/rest/routes.go:230-232, keys:get, keys:rotate, keys:delete), but
sdk/ts has no method for them and no console view calls them. KeysView
rotates a key at once but cannot schedule rotation.

## Slice

- Helper `web/app/src/lib/keyRotationPolicy.ts`: the wire interfaces
  (`RotationPolicy`, `SetKeyRotationPolicyRequest`,
  `KeyRotationPolicyResponse`, `KeyManagementResponse`),
  `getRotationPolicy`, `setRotationPolicy`, `deleteRotationPolicy` over
  `getSDKClient().http.request`, and `toSeconds` / `fromSeconds`.
  GET and DELETE pass the backend as `?backend=`; PUT sends
  `{backend, key_id, policy}`; `next_rotation` is never sent.
- View `web/app/src/views/KeyRotationPolicyView.svelte`: PageHeader
  "Rotation Policy"; key ID and backend inputs with Load; a current-policy
  card (enabled, interval, versions kept, auto rotate, next rotation); a
  form (enabled, auto rotate, interval number + hours/days unit, retain
  versions) with Save and Remove (confirm), busy state, inline validation,
  error Alert.
- Route `#/keys/rotation-policy` (`keyRotationPolicy`), nav entry
  "Rotation Policy" under Keys & Crypto after TPM Policies, gated on
  keys:get.
- One-line-per-place rule: nav.ts one added line, router.svelte.ts two
  (union, path map), App.svelte two (import, dispatch); no other line
  changed there.

## Tests

`web/app/test/view3_key_rotation_policy.test.ts`: load (GET + query,
30 days / 3 versions / next date, "No rotation policy"), save (PUT body,
7 days = 604800, 12 hours = 43200, toast), remove (DELETE after confirm,
declined sends nothing), validation (disabled buttons, bad interval or
retain count shows an error and sends nothing), errors (rejected GET/PUT
shows an Alert).

## Checks

sdk/ts build (dist restored), svelte-auth npm ci, web/app npm ci, the new
vitest file, the whole web/app suite, svelte-check, vite build,
pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

Manual rotation, key versions, access policy, key metadata, KeysView, Go
code, sdk/ts, docs/SPEC.md.

## Results

Results to follow.
