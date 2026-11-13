# Plan: xkey acme renew and enroll (row acme, issue #2085, lane sacmee)

## Objective

Add the next two verbs of the `xkey acme` namespace, as thin callers of the
ACME client through sdk/go (`sdkacme`), on the existing `acmeClient`
interface and `sdkacme.NewACMEClient` constructor built for account and
revoke.

## Commands

- `xkey acme renew --cert <file> --domain <name> [--csr <file>]
  [--challenge <type>] [--authz-type dns|ip|permanent-identifier]
  [--out <file>]`
  - reads the old certificate (`os.ReadFile` + `parsePEMCertificate`),
    builds an `sdkacme.ACMECertificateRequest` (AuthzType, AuthzValue,
    ChallengeType, CSR as DER) and calls
    `RenewCertificate(ctx, oldCert, req)`.
  - writes the renewed certificate as PEM (`CERTIFICATE` block) to --out or
    stdout; never key material.
- `xkey acme enroll --challenge enroll-01|endorse-01|device-attest-01
  [--ip <addr>] [--port 8080] [--listen-host <h>] [--common-name <cn>]
  [--pcr 0,1,..] [--timeout 30s] [--tpm-device <path>] [--tpm-simulator]
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
