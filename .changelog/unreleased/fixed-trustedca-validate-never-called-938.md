- **`pkg/acme/client.New` now validates a standalone `TrustedCA` config before
  it constructs, so an invalid config can no longer start serving (BREAKING:
  a config that constructed today because nothing ever called
  `TrustedCAConfig.Validate` — for example, missing `acme.https_addr` or
  `acme.ca_identifiers` — now fails `New` with a typed
  `*errors.TrustedCAError`; #938).** `TrustedCAConfig.Validate` existed but
  neither `New` nor `Serve` called it (found during #929, which wired only
  the audit-log-path half of `Validate` into place). `New`
  (`trustedca.go`) now calls `tca.config.Validate()` once, after applying
  every `Option` and after the existing CA/storage-factory/QRDB component
  checks, and fails closed with `Validate`'s typed error
  (`errors.MalformedError`, `caerrors.Malformed` — check with
  `errors.Is`/`errors.As`); `WithConfig(nil)` fails the same way instead of
  later panicking on a nil receiver. `Validate` also resolves
  `Audit.LogPath` against `DataDir` (go-xkms#929); that now happens exactly
  once, inside `New`, and `Serve` reads the already-resolved path rather than
  calling `resolveAuditLogPath` a second time.
  Reviewing every `Validate` rule while wiring it in surfaced one that was
  wrong: `TCAACMEConfig.Validate` required `acme.external_url`
  unconditionally, but `TrustedCA.Serve` has always derived an origin from
  the listen address (`AdvertisedURL`) when neither `WithExternalURL` nor
  `acme.external_url` is set (#140) — a supported, tested construction path
  (`TestTrustedCA_Serve_DerivesExternalURLFromListenAddress`) that requiring
  the field would have permanently broken. `acme.external_url` is now
  optional; when set, `Validate` still requires it to parse as an absolute
  HTTPS URL with a host. `acme.ca_identifiers` stays required (RFC 8555
  §8.1: CAA must be checked before issuance, and an empty list gives the
  check nothing to compare against) — `TrustedCA.Serve`'s warn-and-continue
  branch for an empty `ca_identifiers` was dead code once `Validate` enforces
  this at construction, and is removed along with the stale comment
  describing it as non-fatal.
  Every in-repo caller of `New`/`DefaultTrustedCAConfig` that relied on an
  incomplete config constructing is fixed to supply a complete one
  (`pkg/acme/client/*_test.go`); two coverage tests that deliberately probe
  `Serve`'s own built-in address-default fallback with an empty
  `acme.https_addr`/`admin.https_addr` now construct the `TrustedCA` directly
  (bypassing `New`/`Validate`, the same white-box pattern
  `TestTrustedCA_Initialize_NilLoggerPath` already used) since that
  configuration is no longer constructible through the public API.
