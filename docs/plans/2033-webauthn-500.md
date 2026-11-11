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

Not found yet. Lane mf2533b (native, no Docker, on this node):

- Built `./cmd/xkmsd` with the recipe's tags
  (`pkcs8 frost webauthn fido2 codec_cbor codec_json codec_msgpack`), ran
  `run-server.sh` from a copy of the suite directory under /tmp: init, boot,
  barrier unsealed through `open-server-barrier.sh`.
- Drove `registration/begin` + `registration/finish` with
  `pkg/webauthn/client` (`HTTPRelyingParty` + `SoftwareAdapter`, origin
  `https://localhost:18443`): registration **succeeds** (no error, result
  returned). So the plain same-origin finish path, `mintTokens` included,
  works natively with the software authenticator.
- `handleServiceError` (`pkg/webauthn/http/handler.go:303`) logs the cause
  only at Debug (`"webauthn service error"`); the suite's config already sets
  `logging.level: debug`, yet CI's daemon log shows no such line, so that
  handler's logger does not appear to honour the configured level.

## Why the Debug line was dropped (lane mf2533c)

`pkg/api/rest/server.go:399` built the handler as
`webauthnhttp.NewHandler(cfg.WebAuthnService)` without `WithLogger`, so the
handler kept `slog.Default()` (`pkg/webauthn/http/handler.go:38`), which
logs at Info, not the daemon's configured logger. `logging.level: debug`
never reached it. Fixed by commits `test(webauthn): a 500 from the WebAuthn
handler logs its cause at Error` and `fix(webauthn): the WebAuthn handler
logs the cause of a 500 at Error`: the default branch of
`handleServiceError` now logs `"webauthn: internal error"` with the error
text at Error, and the server passes its logger (`WithLogger(log)`). With
these in, CI's daemon log shows the cause of the next 500.

## CI-like native run (lane mf2533c, partial)

- xkmsd built with the recipe's tags (fix included); suite copied to
  /tmp, `run-server.sh` run with `config.yaml` UNCHANGED (relative paths),
  `XKMSD_BIN` set: init, boot and barrier unseal succeed.
- Registration begin + finish with the spec's exact bodies (public
  sign-up: `{email, display_name}` to `/registration/begin`, `X-Session-Id`
  header, finish body `{id, rawId, type, response{attestationObject,
  clientDataJSON}, clientExtensionResults}`) NOT sent yet: the slice hit
  its turn budget. Whether the 500 reproduces is still open.

## Next slice

1. Run the Playwright suite natively (`npm ci`, `npx playwright install
   chromium chromium-headless-shell`, `XKMSD_BIN=... npx playwright test`) to
   see whether the 500 reproduces without Docker; the browser's virtual
   authenticator differs from `SoftwareAdapter` (resident key, attestation
   format, algorithm, `runRegistration` body fields at spec line 95-200).
2. Find where the webauthn `Handler`'s logger is built and why its Debug
   line is dropped; with it visible, the underlying error is in the log.
3. Candidate paths in `runFinishRegistration` (`pkg/webauthn/service.go:467`):
   `finishPublicRegistration` (public sign-up, which the suite uses),
   `saveRegisteredCredential`, then `mintTokens` (`service.go:959`).
