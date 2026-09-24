- **The manufacturer EK certificate download is opt-in and bounded, instead
  of an unconditional, unbounded `http.Get`.** `pkg/tpm2.TPM2.EKCertificate()`
  fell back to `http.Get` against the manufacturer's EK certificate service
  (`https://ekop.intel.com/ekcertservice/`) with no timeout whenever no local
  EK certificate was found — an air-gapped host could block indefinitely, and
  tests exercising the fallback made real network calls. New
  `EKConfig.CertDownload` (`ek.cert-download`, default `false`) gates the
  download; with it off, `EKCertificate` returns the existing
  `ErrEndorsementCertNotFound` sentinel as soon as NV RAM and the certificate
  store are exhausted, and makes no network call at all. With it on, the
  request is bounded by `EKConfig.CertDownloadTimeout`
  (`ek.cert-download-timeout`, `DefaultEKCertDownloadTimeout` 10s when unset)
  via the request context, uses an injectable `*http.Client`
  (`Params.HTTPClient`), and accepts `EKConfig.CertDownloadURL`
  (`ek.cert-download-url`) to point at a non-Intel service. The response is
  parsed as DER or PEM X.509, replacing the previous
  `{"certificate": "..."}` JSON-wrapper parsing the manufacturer service does
  not actually use; a bounded `io.LimitReader` (64KiB) replaces the prior
  unbounded body read. New typed errors `ErrEKCertServiceUnreachable`
  (connection failure, timeout, or non-200 status) and
  `ErrEKCertServiceParseFailed` (response is not a valid certificate), both
  reachable through `errors.Is`. **BREAKING**: a deployment that relied on
  the previous unconditional manufacturer download must now set
  `ek.cert-download: true` explicitly. Tests (tag `tpm_simulator`,
  `ek_cert_download_simulator_test.go`): download disabled proves no HTTP
  call is made (an injected `RoundTripper` fails the test if invoked);
  download enabled against an `httptest` TLS server for a DER response
  (`EKCertificate` end-to-end) and a PEM response
  (`downloadEKCertFromManufacturer` directly); a server that never responds
  proves the request is bounded rather than blocking
  (`ErrEKCertServiceUnreachable` within the configured timeout); a malformed
  response proves `ErrEKCertServiceParseFailed`. Files:
  `pkg/tpm2/tpm.go`, `pkg/tpm2/config.go`, `pkg/tpm2/types.go`,
  `pkg/tpm2/types_test.go`, `pkg/tpm2/ek_cert_download_simulator_test.go`,
  `pkg/tpm2/simharness_simulator_test.go`, `docs/tpm2/engineering.md`,
  `docs/tpm2/user.md` (#761).
