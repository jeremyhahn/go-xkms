# Plan: xkey acme renew and enroll (row acme, issue #2085, lane sacmee)

## Objective

Add the next two verbs of the `xkey acme` namespace, as thin callers of the
ACME client through sdk/go (`sdkacme`), on the existing `acmeClient`
interface and `sdkacme.NewACMEClient` constructor built for account and
revoke.

## Commands

- `xkey acme renew --cert <file> --domain <name> --csr <file>
  --challenge <type> [--authz-type dns|ip|permanent-identifier]
  [--out <file>]`
  - reads the old certificate (`os.ReadFile` + `parsePEMCertificate`),
    builds an `sdkacme.ACMECertificateRequest` (AuthzType, AuthzValue,
    ChallengeType, CSR as DER) and calls
    `RenewCertificate(ctx, oldCert, req)`.
  - writes the renewed certificate as PEM (`CERTIFICATE` block) to --out or
    stdout; never key material.
- `xkey acme enroll --challenge enroll-01|endorse-01|device-attest-01
  [--ip <addr>] [--port 8080] [--listen-host <h>] [--common-name <cn>]
  [--timeout 30s] [--tpm-device <path>] [--tpm-simulator]
  [--data-dir <dir>] [--out-dir <dir>]`
  - checks the challenge name and that --ip is set (unless
    device-attest-01) before the client is called.
  - builds an `sdkacme.ACMEEnrollmentConfig` and calls
    `EnrollDevice(ctx, cfg)`; writes IAK, IDevID and chain as PEM.
  - TPM module: `openTPMWithKeyStore` (sdk/go/localtpm via the xkey TPM
    wiring) then `sdkacme.NewACMEXKMSTPMAdapter(dev.TPM(), dev.Keys())`,
    behind a package var so the test injects a stub `ACMETPMModule`.

## Slices (this lane)

1. Test commit: cobra tests on the fake client (renew request and PEM
   output, enroll config, device-attest-01 without --ip, failures before
   the client for missing/unparsable cert, unknown challenge, missing --ip,
   no key material printed).
2. Feat commit: acme_renew.go, acme_enroll.go, interface + registration.
3. Docs commit: xkey/docs/acme/README.md marks renew and enroll.

## Out of scope

`xkey acme endorse`, the GUI, any change to pkg/acme/client, account and
revoke.

## Results

xkey build + cmd tests pass, sdk/go build passes, make lint 0 issues (2026-11-12).
Renew reuses the package's loadCertificatePEM (as revoke does).

## Codex fix slice (lane sacmej, PR #2126; each test commit before its fix)

- Finding 2: `test(xkey): renew rejects a request the acme client would
  reject`, `fix(xkey): renew requires a challenge type and a CSR, as the acme
  client does` (CLI and GUI require both and run CertificateRequest.Validate).
- Finding 4: `test(xkey): acme enrollment ends at its timeout and releases the
  TPM`, `fix(xkey): acme enrollment honours its timeout` (ACMEEnrollContext).
- Finding 1 (lane sacmek): `test(xkey): acme enrollment runs the selected
  challenge protocol`, `fix(xkey): dispatch acme enrollment on the selected
  challenge` (services.RunACMEEnrollment, shared by the GUI and the CLI:
  enroll-01 EnrollDevice, device-attest-01 DeviceAttest, endorse-01
  RequestEndorsementKeyCertificate; unknown challenge is an error). The tests
  use a fake of the ACMEClient interface, not the package's test server.
- Finding 3 (lane sacmek, resumed): `test(xkey): acme renewal answers a
  pending http-01 challenge`, `fix(xkey): acme renewal serves the http-01
  token for a pending authorization` (services.SetACMERenewSolver, shared by
  the GUI and the CLI: http-01 serves the key authorization from the pkg/acme
  http-01 Responder on --http-addr / httpAddr, default :80, until cleanup;
  dns-01 is an error naming the missing DNS provider, since xkey has none).
  The tests use a CA stand-in that calls ChallengeSetup as the client does
  and fetches the token over HTTP.
- Codex findings 1 to 4 of the sacmei review are fixed.
- lane-verify (check-wailsjs): `fix(xkey): regenerate wails bindings for the
  acme renew http address` commits the ACMERenewRequest.httpAddr binding.
- lane-verify (check-wailsjs, lane af2126d): the deadline fix dropped
  ACMEEnrollRequest.PCRs (device-attest-01 evidence carries none), so `fix(xkey):
  drop the GUI PCRs field with the regenerated wails bindings` commits
  models.ts and removes the PCRs input and the hand-written `pcrs` type.
