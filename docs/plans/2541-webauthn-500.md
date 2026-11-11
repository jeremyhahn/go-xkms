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
3. Next: a Go test that fails on the cause, then the fix, then rerun the six
   tests.

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

## Out of scope

The cross-origin test (CORS, #2033). Suite assertions are unchanged.
