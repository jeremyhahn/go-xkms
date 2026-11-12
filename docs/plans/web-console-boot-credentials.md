# Web console: Boot Credentials view (epic #1443, lane suin)

## Gap

The server can wait for a boot credential (an unseal secret or PIN). Main
serves `GET /api/v1/credentials/strategy` (credentials:strategy) and
`POST /api/v1/credentials/submit` (credentials:submit), and the TS SDK has
`credentials.strategy` and `credentials.submit`, but no console view calls
them: an operator must use xkmsctl or curl.

## The view

- `web/app/src/views/BootCredentialsView.svelte`, titled "Boot Credentials".
- Strategy card: the strategy name and an auto-unseal `StatusBadge`.
- Submit form: credential name and a password-type secret field. The secret
  is sent as `textToB64(secret)`, cleared after every attempt and never
  rendered or toasted. The returned status goes in a success toast.
- A rejected `strategy` (routes not wired) shows an info `Alert`; a rejected
  `submit` shows an error `Alert` with the server message.

## Route and nav

- Route `#/credentials/boot`, name `bootCredentials`.
- Nav entry in Security after Platform Secrets, icon `KeyRound`, requires
  credentials:strategy.
- One added line per place in nav.ts, router.svelte.ts (two places) and
  App.svelte (two places), at fixed anchors, no other change there: the rule
  shared with lanes suia-suii and suij, suik, suil, suim, suio, so merges
  are trivial.

## Tests

`web/app/test/view3_boot_credentials.test.ts`: mount, submit, secrecy,
validation, errors. Committed before the view (ruling 286).

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the whole
web/app suite (NODE_OPTIONS=--no-experimental-webstorage), svelte-check, the
vite build, pkg/api/rest -race, sdk/go build, make lint.

Out of scope: the session `GET /api/v1/credentials` list, Go code, sdk/ts,
docs/SPEC.md.

## Results

- sdk/ts npm ci + build: pass (the rebuilt tracked sdk/ts/dist was restored, not committed).
- sdk/ts/svelte-auth npm ci: pass.
- web/app npm ci: pass.
- vitest test/view3_boot_credentials.test.ts: pass, 6 tests.
- web/app npm test (NODE_OPTIONS=--no-experimental-webstorage): pass, 51 files, 418 tests.
- npm run check: 2 errors, both baseline (UsersView.svelte:121 and view2_users.test.ts:51, role/roles).
- vite build: pass.
- go test -race ./pkg/api/rest/ (codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass.
- Simplify pass: nothing to remove.
- The feat(web) view commit has the test(web) subject by mistake (no amend
  allowed); the docs(web-console) commit says so.
