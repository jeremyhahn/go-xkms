# Web console: User Detail view (row 1443, lane sujo)

## Gap

Main serves GET `/api/v1/users/{username}` (users:read) and sdk/ts has
`users.get`, but no console view calls it. UsersView only lists, creates,
enables, disables and deletes. Operators need one user's full record,
including the numeric ID the N-factor endpoints key on.

## Plan

- Helper `web/app/src/lib/userDetail.ts`: `loadUser(username)` over
  `getSDKClient().users.get` (trims the name); `isNotFound(err)` (status 404).
- View `web/app/src/views/UserDetailView.svelte`: PageHeader "User Detail"
  (read-only), a lookup card (username input, Look up button, Enter looks up,
  busy state, blank never calls the API), a details card (ID as a string in
  monospace, username, display name, role badges, enabled via StatusBadge,
  created, last login or "Never"), Alert for errors ("User not found" on 404).
- Route `#/users/detail` -> `userDetail`; nav entry "User Detail" under
  Identity & Access after Users, requires users:read.
- One added line per place: nav.ts (1), router.svelte.ts (2), App.svelte (2);
  no other line there changes.

## Tests

`web/app/test/view3_user_detail.test.ts`: empty input, load (trim, string
ID unchanged, roles, enabled, times), never logged in, disabled, not found
(404) and other error.

## Checks

sdk/ts build, svelte-auth npm ci, web/app npm ci, the new vitest file, the
whole web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go
build, make lint.

## Out of scope

User create/enable/disable/delete, credentials and certificate binding,
roles editing, UsersView, Go code, sdk/ts, docs/SPEC.md.

## Results

- sdk/ts build: pass (tracked sdk/ts/dist restored after).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_user_detail.test.ts: pass (7 tests).
- vitest whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage): pass (51 files, 419 tests).
- svelte-check: baseline only, run against a fresh sdk/ts build (UsersView.svelte:121 and test/view2_users.test.ts:51, role vs roles); the stale tracked dist has `role` and flags this view's `roles` instead.
- vite build: pass.
- go test -race ./pkg/api/rest/: pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues).
