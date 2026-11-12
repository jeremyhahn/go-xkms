# Plan: xkey acme endorse (row acme, epic #2085)

## Objective

Add `xkey acme endorse`, the last verb of the `xkey acme` namespace. It is a
thin caller of `RequestEndorsementKeyCertificate(ctx, *sdkacme.ACMEEnrollmentConfig)
(*x509.Certificate, error)` on `*sdkacme.ACMEClient` (sdk/go alias of
pkg/acme/client.Client). It obtains an EK certificate through the endorse-01
challenge, for TPMs without a manufacturer EK certificate.

## Command

`xkey acme endorse --ip <addr> [flags]`

- `--ip` (required; endorse-01 validation needs it, checked by the CLI before
  the client is called)
- `--port`, `--listen-host`, `--common-name` (client derives "{cn}-ek"),
  `--timeout`, `--out` (PEM file; stdout when empty)
- TPM flags shared with enroll (`--tpm-device`, `--tpm-simulator`, data dir via
  `resolveDataDir`).

Challenge is fixed to `sdkacme.ACMEChallengeTypeEndorse01` (no --challenge).
The TPM module comes from the same injectable source enroll uses (shared
helper, no second copy of the TPM wiring). Output is only the certificate as a
PEM "CERTIFICATE" block, never key material.

## Slices (commits, in order)

1. docs(plans): this file.
2. test(xkey): cobra tests against the fake client: config passed (endorse-01,
   IP, port, common name, injected TPM module) and PEM written; missing --ip
   fails before the client is called; client error returned and --out not
   written.
3. feat(xkey): acme endorse command, `acmeClient` interface method, command
   registration.
4. docs(xkey): README marks endorse implemented.

## Out of scope

GUI; sdk/go and pkg/acme/client changes; account, revoke, renew, enroll
behaviour.

## Results

xkey go build + go test (codec tags) ./cmd/xkey/cmd/... pass; sdk/go go build passes; make lint passes (0 issues on every module and tag set).
The TPM module source was already shared (openACMETPMModuleFunc), so acme_enroll.go needed no change; the fake client lives in acme_test.go.
