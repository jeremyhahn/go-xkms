# 2541: name and fix the WebAuthn browser suite's same-origin 500 (CA m2541)

## Objective

`make integration-test-webauthn-browser`: the six same-origin tests in
`test/integration/webauthn-browser/tests/rp-ceremony.spec.ts` (318, 338,
354, 380, 395, 431) fail with `{"error":"internal_error"}`. Name the cause,
fix it, and get the six to pass. The cross-origin test (CORS, #2033) is out
of scope.

## Slices

1. Done: the logger test and fix (from c304bf62cb / 5b83c3e637). The REST
   server passes its logger to the WebAuthn handler, and a 500 logs its cause
   at Error.
2. Done: the cause was reproduced in real Chrome on this node (Playwright +
   CDP virtual authenticator, xkmsd built with the recipe's tags, all six
   same-origin tests red). The cause is below.
3. Done: three layers, each with a failing Go test and its fix (user store
   service context, the principal's WebAuthn grant, the refresh store
   service context); the six same-origin tests pass natively in Chrome.

## Cause (Chrome run on this node, 2026-11-11)

The [WebServer] log line, once per test:

    ERROR webauthn: internal error error="get user by email: qrdb user lookup: qrdb/auth: unauthenticated: no valid credentials provided"

- The failing request is **registration/begin**, not finish. The spec's
  `runRegistration` returns begin's body when begin is not ok, and the
  assertion text at line 323 still says "registration finish failed".
  The prefix `get user by email` comes from `Service.BeginRegistration`
  (`pkg/webauthn/service.go`, the `s.users.GetByEmail` probe), via
  `qrdbUserStore.GetByEmail` -> `mapNotFound` ("qrdb user lookup").
- The qrdb client (`p.QRDBClient.Users()`, `pkg/api/rest/host.go:417`)
  refuses the call as unauthenticated in Chrome's request context. Earlier
  lanes found that a native Go client sending the same bodies gets 200.
  So a header that Chrome sends and the Go client did not changes the
  request context the qrdb call sees.
- This is not a startup race: all six tests fail, not only the first.

## Lead for slice 3

- Chrome's same-origin POST sends `Origin: https://localhost:18443` and
  `Sec-Fetch-*`. The earlier Go clients did not send an Origin header.
  `pkg/api/rest/middleware.go:160` is the one REST middleware that reads
  `Origin`. Read it first: check whether a request with Origin takes a path
  that drops or replaces the qrdb principal in the context.
- Reproduce in Go: an httptest request to `/api/v1/webauthn/registration/begin`
  with an `Origin` header (plus `Sec-Fetch-Site: same-origin`), through the
  REST server's middleware chain, expecting 200. Bisect the headers if
  Origin alone does not do it.
- The fix must not weaken an auth check. State the change in the fix
  commit.

## Repro plan (slice wa2541c)

- Handler chain: the REST server's router (CORS, logging, recovery, the
  public WebAuthn mount) in front of `webauthnhttp` begin, with the
  qrdb-backed user store, as `pkg/api/rest/host.go` wires it.
- Header set: Chrome's same-origin POST (`Origin: https://localhost:18443`,
  `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: cors`,
  `Content-Type: application/json`), then bisected against a request with
  none of them.
- Test file: a `_test.go` next to the code the cause names (the qrdb user
  store or the REST WebAuthn mount), failing before the fix.

## Findings

- Cause (wa2541d, coordinator-checked on a1ae1253a7): the Origin lead is
  not it. `pkg/webauthn/qrdb_userstore.go` calls the qrdb users and
  credentials clients on the caller's request context, while every DAO runs
  on the node's service principal through `datastore.WithCallContext`
  (`node.ServiceContext`). `pkg/api/rest/host.go` builds the store without
  that binder, so an anonymous browser `registration/begin` reaches qrdb
  with no principal: `qrdb/auth: unauthenticated`.
- Fix (wa2541e): `QRDBUserStoreOptions.CallContext` (type
  `qrdbstorage.CallContext`); every users/creds call runs on the bound
  context; both `BuildWebAuthnService` call sites pass the node's service
  context binder.
- Second layer (wa2541e native rerun after the binder): begin passes, finish
  answers 500 with `qrdb/auth/rbac: permission denied: qrdb-service:xkms
  cannot read on users`. The running xkmsd's service principal holds no user
  permission (`pkg/embeddednode/serviceprincipal`: only `xkmsd init` adds
  its ceremony grant). Fix: a WebAuthn grant (`users:read`, `users:create`,
  `users:update`, `users:delete`, go-qrdb `pkg/permission` names),
  registered only when the server builds the WebAuthn service over the
  embedded node. No go-qrdb change.
- Second layer fixed (wa2541f): `serviceprincipal.RegisterWebAuthnGrant`,
  called in `pkg/server` before `rest.BuildWebAuthnService`. Native rerun:
  the users calls pass; all six still answer 500 with a third layer,
  `generate token: auth/token: refresh store put failed: qrdb/auth:
  unauthenticated: no valid credentials provided`: the token service's
  refresh store calls qrdb on the anonymous request context.
- Third layer fixed (wa2541f): `token.BindRefreshStore` +
  `TokenIssuerParams.CallContext`; `pkg/server` passes
  `Node.ServiceContext` (kv permissions already in the base grant). Native
  rerun in Chrome on this node: the six same-origin tests pass; the
  cross-origin test still fails with `Failed to fetch` (CORS, #2033).
- Open: `NewHostServer` (API module hosts) builds its token issuer without
  a CallContext, and the issuer's qrdb user resolver (refresh re-check)
  still runs on the caller's context; neither is in the six tests.
- Cross-origin fixed (wa2541g): #2033's CORS test and fix brought in
  (`pkg/apimodule` wraps each unified-surface route with the REST server's
  `CORSMiddleware` and answers preflights). Native rerun in Chrome on this
  node: 7 of 7 browser tests pass, the cross-origin test included.
- Known gap (go-qrdb, ruling 159): Codex's P1 on #2033, CORS headers on the
  host's 401/403 responses, sits in go-qrdb; no go-qrdb change here.

## Out of scope

CORS headers on the host's 401/403 responses (go-qrdb). Suite assertions are unchanged.

## Codex findings on wa2541g (lane wa2541i)

- P1 (1) pkg/api/rest/host.go:766-776 (reported :826): NewHostServer builds TokenIssuerParams without CallContext, so QRDBRefreshStore.Save fails with ErrUnauthenticated on an authentication-enforcing node after the credential is saved and Finish returns 500. Fix: pass the host's binder into BuildTokenIssuer; test ceremony completion against an authenticated node.
- P1 (2) pkg/api/rest/host.go:216-222: QRDBUserResolver calls GetUser/GetUserByUsername on the request context; POST /api/v1/auth/refresh is public, so a valid refresh fails 401. Fix: bind the resolver's lookup context, keep the current-account checks; test a real refresh request.
- P1 (3) pkg/api/rest/host.go:282-290: the adapter puts the base64 WebAuthn handle in Subject and JWTAuthenticator rebuilds the identity with UserID unset; go-qrdb finalizeIdentity/accountKey looks the handle up as a username, so roles never load and keys:read is refused after passkey login. Fix: translate the verified token into qrdb's immutable user identity; test an authorized request through the real module middleware.

### Lane wa2541i status at its turn cap

- P1 (1) done: test 955fc155e, fix ded5754bb. P1 (2) done: tests 81137d408 + e7d3a3f3d, fix 76f673f41 (token.BindUserResolver).
- P1 (3) remains; no go-qrdb change is needed. Planned fix: in JWTAuthenticator.validateToken (pkg/auth/jwt.go), when the `sub_kind` claim is `user_handle`, decode Subject with decodeWebAuthnHandle (pkg/auth/refresh_resolver.go) and call identity.BindUser(id, username claim). That sets UserID and the decimal Subject, so qrdb loads roles by id. Test first: an enforcing node (helpers in pkg/api/rest/host_callcontext_test.go) with a user holding a keys:read role, a token minted with sub_kind=user_handle, and the bearer sent through node.AuthMiddleware().RESTMiddleware (qrdb pkg/auth/middleware) or the module's AuthenticateHTTP, expecting authorization to succeed.
- Not run yet: the race tests, vet with TEST_TAGS, the webauthn-browser suite, and make lint.
