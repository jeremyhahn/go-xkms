# xkey acme renew and enroll (row acme, issue #2085, lane sacmed)

## Objective

Add the next two verbs of the `xkey acme` namespace as thin callers of
pkg/acme/client through sdk/go, on the existing `acmeClient` interface and
the `sdkacme.NewACMEClient` constructor built by the account/revoke slice.

## Commands

- `xkey acme renew --cert <pem file> --domain <name> [--domain ...] --out <file>`
  - parses the old certificate (PEM) before the client is built;
  - calls `RenewCertificate(ctx, oldCert *x509.Certificate, req *sdkacme.ACMECertificateRequest)`;
  - writes the renewed certificate chain as PEM; the private key is never
    written or printed.
- `xkey acme enroll --challenge enroll-01|device-attest-01 [--ip <addr>]`
  - validates the challenge type and requires `--ip` for enroll-01 before
    the client is called; device-attest-01 needs no `--ip`;
  - calls `EnrollDevice(ctx, *sdkacme.ACMEEnrollmentConfig)` and prints the
    result summary (no key material).

## TPM module for enroll

Taken from an existing sdk/go surface only (sdk/go/acme re-exports
ACMETPMModule; adapter ACMEXKMSTPMAdapter or the xkey TPM wiring). If no
sdk/go surface reaches it without a pkg/ import, the gap is named here.

## Slices (this lane)

1. Test commit: cobra tests against the fake client (renew request and PEM
   output, enroll config mapping, input errors before the client, no key
   material in output).
2. Feat commit: acme_renew.go, acme_enroll.go, interface methods and
   registration in acme.go.
3. Docs commit: xkey/docs/acme/README.md marks renew and enroll implemented.

## Out of scope

`xkey acme endorse`, the GUI, any change to account and revoke, pkg/acme/client.

## Results

(filled at the end of the lane)
