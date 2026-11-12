# Web console: User Certificate Binding (row 1443, lane suiu)

## Gap

Main serves `GET /api/v1/users/{username}/credentials` (users:read) and
`POST /api/v1/users/{username}/cert-bindings` (users:update), and the TS SDK
has `users.credentials` and `users.bindCert`, but the console never shows a
user's credentials or binds a client certificate thumbprint, so a user cannot
be set up for certificate (PIV / mTLS) login from the console.

## The view

`web/app/src/views/UserCertBindingView.svelte`, titled "Certificate Binding":

- a username input with a Load button (disabled until a username is set);
- the credentials list (name and id), "No credentials" when empty;
- a bind form: thumbprint (trimmed, colons and spaces removed, must be hex)
  and a not-after date (sent as `Math.floor(Date.parse(value) / 1000)`),
  a Bind button with a busy state; success toast with the returned status,
  then the credentials reload;
- an error `Alert` for rejected calls.

Route `#/users/cert-bindings` (`userCertBinding`); nav entry "Certificate
Binding" in the Certificates & CA section, requires users:update.

## One line per place

Shared with lanes suia-suit and suiv: exactly one added line in nav.ts, two in
router.svelte.ts (union, path map), two in App.svelte (import, dispatch), at
the anchors in the brief, and no other change there.

## Tests

`web/app/test/view3_user_cert_binding.test.ts`: button gating and nothing on
mount; Load lists credentials and the empty state; Bind sends the normalised
thumbprint and not_after_unix, toasts and reloads; non-hex thumbprint shows an
inline error; rejected calls show an error Alert.

## Checks

sdk/ts build, svelte-auth and web/app npm ci, the new vitest file, the whole
web/app suite, svelte-check, vite build, pkg/api/rest -race, sdk/go build,
make lint.

## Results

- sdk/ts build, svelte-auth npm ci, web/app npm ci: pass (sdk/ts dist/ restored, not committed).
- vitest test/view3_user_cert_binding.test.ts: pass (7 tests).
- vitest whole web/app suite (NODE_OPTIONS=--no-experimental-webstorage): pass (51 files, 419 tests); store_nav.test.ts unchanged.
- svelte-check: baseline only (UsersView.svelte:121 and test/view2_users.test.ts:51, role/roles).
- vite build: pass.
- go test -race pkg/api/rest: pass.
- sdk/go go build: pass.
- make lint: pass.
- Note: the feat commit carries the test commit's subject by mistake (message file not rewritten); its content is the view, route, App dispatch and nav line.
