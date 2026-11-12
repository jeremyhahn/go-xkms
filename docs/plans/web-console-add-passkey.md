# Web console: Add Passkey (row 1443, lane suio, slice 15)

## Gap

A signed-in user has no console path to add a backup passkey. RegisterView
enrolls only an account's first passkey (signed out, through svelte-auth) and
refuses an account that already has one. The server offers
POST `/api/v1/webauthn/credentials/begin` (session auth, the session's own
account) and the TS SDK has `auth.webAuthnAddCredentialBegin` and
`auth.webAuthnRegisterFinish`, but no view uses them.

## The view

- `web/app/src/views/AddPasskeyView.svelte`: `PageHeader` "Add Passkey", one
  sentence on what a second passkey is for, an Add passkey button with a busy
  state, a success line, an error `Alert`, and an info `Alert` when the browser
  has no `navigator.credentials`.
- Ceremony: begin -> `navigator.credentials.create({ publicKey:
  parseCreationOptions(options) })` -> `webAuthnRegisterFinish(sessionId,
  encodeAttestationResponse(cred))`. The returned token is never rendered or
  stored; the current session stays as it is.
- Route `#/account/passkeys` (route name `addPasskey`).
- Nav entry "Add Passkey" in Identity & Access after Users, icon
  `Fingerprint`, capability `webauthn` (shown only where WebAuthn is wired).

## One line per place

nav.ts, router.svelte.ts (union + path map) and App.svelte (import +
dispatch) are shared with lanes suia-suii and suij, suik, suil, suim, suin.
This lane adds exactly one line at each named anchor and changes nothing
else there, so merges are trivial.

## Tests

`web/app/test/view3_add_passkey.test.ts` (test commit before the feat commit):
add (begin, create with parsed options, finish, success toast), token (never
shown), cancel (NotAllowedError -> "Passkey creation was cancelled", no
finish), unsupported (button disabled, info Alert), errors (begin/finish
rejection -> error Alert).

## Docs

docs/web-console/user.md Navigation table, Identity & Access row; changelog
entry `.changelog/unreleased/added-1443-console-add-passkey.md`.

## Checks

sdk/ts build, svelte-auth npm ci, web/app npm ci, vitest (new file, then
whole suite with NODE_OPTIONS=--no-experimental-webstorage), svelte-check,
vite build, `go test -race` on ./pkg/api/rest/, sdk/go build, make lint.

Out of scope: RegisterView/LoginView, svelte-auth, passkey listing/removal,
Go code, sdk/ts, xkey, web/desktop, docs/SPEC.md.

## Results

Results to follow.
