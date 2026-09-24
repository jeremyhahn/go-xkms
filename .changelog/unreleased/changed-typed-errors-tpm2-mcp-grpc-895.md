- **`pkg/tpm2/certify_verify.go` and `pkg/api/mcp/handlers_ssh.go` no longer
  build errors inline with `fmt.Errorf`/`errors.New` inside function
  bodies** (go-xkms#895 batch A). `certify_verify.go`'s `VerifyCertify`,
  `VerifyCertifyRaw`, `signatureFromScheme`, `verifyCertifySignature` and
  `rsaPublicFromArea` used 28 ad-hoc `fmt.Errorf("%w: ...", ErrCertifyX,
  err)` call sites to attach context to the package's certify-failure
  sentinels; each now builds the identical rendered message through the
  package's existing `pkg/errs` typed wrappers (`errs.Detail` for a fixed
  suffix, `errs.Joined` for a wrapped cause with an optional detail phrase),
  the same style `attestation.go` and `eccpub.go`'s
  `ecdsaPublicFromArea` already used in this package — `rsaPublicFromArea`
  had no direct test for either of its two failure branches, so
  `TestRSAPublicFromAreaWrapsAsCertifyMalformed` and
  `TestRSAPublicFromAreaWrapsUniqueMismatchAsCertifyMalformed` were added
  alongside the conversion, mirroring the existing
  `TestECDSAPublicFromAreaWrapsAsCertifyMalformed`. `handlers_ssh.go`'s four
  `mapSSHError(&SSHInvalidParamsError{Err: errors.New("...")})` required-field
  checks (`ssh.keys.sign`, `ssh.knownHosts.verify` x2,
  `ssh.authorizedKeys.verify`) now wrap package-level sentinels
  (`ErrSSHDigestRequired`, `ErrSSHHostRequired`, `ErrSSHPublicKeyRequired`,
  `ErrSSHFingerprintRequired`), matching the sentinel-per-required-field
  convention `handlers_user.go`/`handlers_password.go` already use in this
  package; their JSON-RPC `ErrCodeInvalidParams` (-32602) mapping through
  `mapSSHError`/`KeyOpError` is unchanged, and the existing tests that
  previously asserted only on `err.Error()` substrings now assert
  `errors.Is` against the new sentinels and the mapped code directly.
  `pkg/api/grpc` was audited with the same method and carries no inline
  `errors.New`/`fmt.Errorf` construction to convert: every match there is
  already a package-level sentinel declaration.
