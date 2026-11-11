# 2033: same-origin WebAuthn registration 500 in main's Integration

## Symptom

Main 4be4169bea, `Integration [integration image]`, step `make integration-test`:
`make integration-test-webauthn-browser` (Makefile:2609) fails 7 Playwright tests in
`test/integration/webauthn-browser/tests/rp-ceremony.spec.ts`.

- 1 cross-origin test (`Failed to fetch`, line 457): the CORS gap, covered by
  commits 83bc2955d9 + 1b7b59fd9c and the go-qrdb finding in fc4c7480f5.
- 6 same-origin tests (lines 318, 338, 354, 380, 395, 431) fail at
  `runRegistration` (line 113) with
  `registration failed: {"error":"internal_error","message":"internal server error"}`.

The daemon log in CI shows no WARN or ERROR line for these 500s.

## Known path (lane mf2533a, read, not run)

- Call: `POST /api/v1/webauthn/registration/finish` (begin succeeds).
- Mapping: default branch of `handleServiceError` in `pkg/webauthn/http/handler.go`
  turns an unclassified error into `internal_error` / 500 without logging it.
- Service path: `FinishRegistration` (handler) -> `FinishRegistrationPair` ->
  `finishRegistrationUser` -> `mintTokens` in `pkg/webauthn/service.go`.

## Underlying error

To be filled by the reproduction.
