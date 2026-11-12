# xkey acme renew and enroll (issue #2085, slice 2)

Row: acme (docs/SPEC.md:155). Slice 1 (docs/plans/acme-account-revoke.md)
built `xkey acme account` and `xkey acme revoke` on the `acmeClient`
interface in xkey/cmd/xkey/cmd/acme.go. This slice adds two verbs on the
same interface and constructor; xkey imports sdk/go only.

## Commands

`xkey acme renew --cert old.pem --csr new.csr --domain host [--http-addr :80] [--out new.pem]`

- Reads the old certificate (PEM) and the CSR (PEM, the new key stays with
  the operator), then calls
  `RenewCertificate(ctx, oldCert, &sdkacme.ACMECertificateRequest{AuthzType: dns, AuthzValue: domain, ChallengeType: http-01, CSR: der, ChallengeSetup/Cleanup})`.
- The http-01 answer is served by `sdkacme.NewHTTP01Responder` on
  --http-addr for the life of the challenge.
- Writes the renewed certificate as PEM to --out or stdout. No key is read
  beyond the account key, and none is printed.

`xkey acme enroll --challenge enroll-01|device-attest-01 [--ip addr] [--port 8080] [--listen-host h] [--common-name cn] [--pcr n ...] [--key-store dir] [--out file]`

- Calls `EnrollDevice(ctx, &sdkacme.ACMEEnrollmentConfig{Challenge, IPAddress, Port, ListenHost, CommonName, PCRSelection, TPMModule})`.
- --ip is required for enroll-01; device-attest-01 needs none.
- Writes the IAK certificate, the IDevID certificate and the chain as PEM.
- TPM module: xkey's own TPM wiring (`openConfiguredTPM`, the configured
  device or simulator, sdk/go `TrustedPlatformModule`) wrapped by
  `sdkacme.NewACMEXKMSTPMAdapter` with a key backend from
  `xkms.NewTPMStorageFactory(logger, --key-store)` (the device-attest-01
  certificate key blob lives there). No new sdk/go surface is needed.
- The TPM opener is a package variable so tests run without a TPM.

## Tests (test commit before the feat commit, ruling 286)

- renew: the parsed old certificate and the request (domain, http-01, CSR
  DER) reach the client; the output is the certificate PEM, no key.
- enroll: enroll-01 with --ip and device-attest-01 without --ip build the
  matching ACMEEnrollmentConfig; the result is written as PEM.
- Failures before the client is called: missing or unparsable --cert or
  --csr, missing --domain, unknown --challenge, enroll-01 without --ip.
- No output carries key material.

## Out of scope

- `xkey acme endorse` (endorse-01) and the GUI: later slices.
- Any change to pkg/acme/client, account or revoke.

## Result

- (filled at the end of the slice)
