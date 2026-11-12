# Web console: Password Access Mode (lane suim, row 1443, slice 13)

## Gap

The password store's access mode (`pin_per_operation` or `session_based`,
pkg/staticpw/access.go) can be changed only with xkmsctl. Main already serves
POST `/api/v1/passwords/access-mode` (permission passwords:write) and the TS SDK
has `passwords.setAccessMode`, but no console view calls it.

## The view

- web/app/src/views/PasswordAccessModeView.svelte, route `#/passwords/access-mode`.
- `PageHeader` "Password Access Mode"; a store status line from `passwords.status()`.
- A radio group with the two modes and one sentence each.
- Apply (disabled until a mode is chosen and the store is available) opens a
  confirm step naming the new mode; Confirm calls `setAccessMode({mode})` and
  shows the response message in a success toast; Cancel calls nothing.
- The last mode set in this session ("not known" before; the status carries no mode).
- Errors (400/501/503 messages) in an error `Alert`; the earlier mode stays on screen.

## Shared files: one line per place

nav.ts (one entry after Passwords, requires passwords:write, capability
passwords), router.svelte.ts (one union member, one path), App.svelte (one
import, one dispatch). Lanes suia-suii and suij, suik, suil, suin, suio touch
the same places; each adds exactly one line per place and changes no other line.

## Tests

web/app/test/view3_password_access_mode.test.ts: mount (status once, unavailable
store shows info Alert and disables Apply), apply session_based (confirm, call,
toast; Cancel calls nothing), apply pin_per_operation, errors (501 message in an
error Alert, earlier mode kept), validation (Apply disabled until chosen).

## Checks

sdk/ts build, svelte-auth npm ci, web/app npm ci, the new vitest file, the whole
web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check, vite
build, pkg/api/rest -race, sdk/go build, make lint.

## Out of scope

PasswordsView and its tests, vault verbs, Go code, sdk/ts, xkey, web/desktop,
docs/SPEC.md.

## Results

Results to follow.
