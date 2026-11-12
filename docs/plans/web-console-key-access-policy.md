# Web console: Key Access Policy view (row 1443 UI slice, lane suja)

Row: web-console, Key Access Policy in the console (docs/SPEC.md:139).

## Gap

Main serves GET, PUT and DELETE `/api/v1/keys/{id}/policy` (keys:get,
keys:rotate, keys:delete; pkg/api/rest/routes.go:227-229), but sdk/ts has
no method for them and no console view calls them. KeysView's "policy" is
the TPM policy select, a different thing.

## Plan

1. Helper `web/app/src/lib/keyAccessPolicy.ts`: `KeyPolicy`, `KeyUsage`,
   the response interfaces, `KEY_USAGES`, and `getKeyPolicy`,
   `setKeyPolicy`, `deleteKeyPolicy` over `getSDKClient().http.request`.
   GET and DELETE pass `?backend=`; PUT sends `{backend, key_id, policy}`.
2. View `web/app/src/views/KeyAccessPolicyView.svelte`: `PageHeader`
   "Key Access Policy"; key ID and backend inputs with Load; a form with
   one checkbox per operation, allowed and denied principal lists (add and
   remove), expiry date, max usage count, rotation-required and MFA
   checkboxes; Save and Remove policy (after confirm) with a busy state;
   inline validation; `Alert` for errors.
3. Route `#/keys/access-policy` (`keyAccessPolicy`), nav entry under
   Keys & Crypto after TPM Policies, requires keys:get.
4. One added line per place: nav.ts (1), router.svelte.ts (2: union and
   path map), App.svelte (2: import and dispatch). No other line changes
   there; clashes with sibling UI lanes are resolved at merge.
5. Docs: Navigation table row in docs/web-console/user.md; changelog entry.

## Tests (web/app/test/view3_key_access_policy.test.ts, committed first)

- load fills the form and version; no policy shows the default message.
- save sends PUT with empty fields omitted; version and success toast.
- remove sends DELETE after confirm; a declined confirm sends nothing.
- validation: buttons disabled without key/backend; principal in both
  lists, bad usage cap, past expiry block the PUT with an inline error.
- errors: rejected GET or PUT shows an error Alert.

## Checks

sdk/ts build (dist restored), svelte-auth and web/app npm ci, the new
vitest file, the whole web/app suite, svelte-check, vite build,
pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

TPM policies, rotation policy, key metadata, KeysView, Go code, sdk/ts,
docs/SPEC.md.

## Results

Results to follow.
