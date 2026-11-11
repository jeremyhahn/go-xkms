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

## CI-like native run (lane mf2533d): no 500

- xkmsd built to /tmp with the recipe's tags (logger fix included); the
  suite and `build/docker/devcontainer/scripts` copied to a /tmp tree with
  the repository layout; the suite's own `run-server.sh` run with
  `config.yaml` UNCHANGED (relative paths), `XKMSD_BIN` set.
- The daemon logs, at init and at boot, `WARN volume pool: failed to open
  volume; pool will not be served on this node ... invalid path
  ".runtime/storage/tenant-volumes": must be an absolute path` — the same
  warning as CI.
- A /tmp Go program sent `runRegistration`'s public sign-up exactly
  (`POST /api/v1/webauthn/registration/begin` `{email, display_name}`, then
  `/registration/finish` with header `X-Session-Id` and body `{id, rawId,
  type, response{attestationObject, clientDataJSON}, clientExtensionResults:
  {}}`, origin `https://localhost:18443`), the attestation built by
  `SoftwareAdapter`: finish answers **200** with `token`, `refresh_token`,
  `user_id`. Six concurrent registrations: all 200. No Error line, no 500.
- So the relative volume path does NOT cause the 500 (the pool is
  unserved natively too, and finish succeeds); the suite config is not the
  cause. Nothing was changed in `config.yaml` or `run-server.sh`.
- Side finding: the same finish with `clientExtensionResults:
  {"credProps":{"rk":true}}` (not requested by begin) answers 401
  `verification_failed`, not 500. Chrome reports no credProps unless it is
  requested, so this is not the browser's body.

## Request differences left (browser vs this run)

The JSON field set is identical. What differs is inside the two base64url
blobs, which the CDP virtual authenticator (`ctap2`, `usb`,
`hasResidentKey`, `hasUserVerification`, `isUserVerified`) produces:

1. `attestationObject`: Chrome's authenticator data flags (UV set, a
   resident/discoverable credential for `residentKey: "preferred"`, BE/BS
   bits), its AAGUID, and the COSE key it chose from `pubKeyCredParams`;
   `SoftwareAdapter`'s may differ in each.
2. `clientDataJSON`: Chrome adds `crossOrigin: false` and may add
   `other_keys_can_be_added_here`; `SoftwareAdapter` builds its own
   `CollectedClientData`.
3. Environment: CI runs in the integration image (Docker), with the
   Playwright readiness probe's TLS handshakes; workers: 1, retries: 0.

## Next slice

1. With the logger fix (commits c304bf62c + 5b83c3e63) in a CI run, CI's
   daemon log now shows the Error line `"webauthn: internal error"` with
   the cause of the 500: read it there (one CI run of #2033), or
2. reproduce Chrome's blobs: build the attestation with UV + discoverable
   flags and Chrome's clientDataJSON keys, and send them as above.
