- **Library code in `pkg/ssh` and `pkg/ca` no longer discards errors with
  `_ =`.** `pkg/ca/config.go`'s `Identity.GetSignatureAlgorithm` silently
  defaulted an unrecognized ECDSA curve name to `ECDSAWithSHA256`; it now
  returns the `types.ErrUnknownCurve` detail from `types.ParseCurve`, and
  `Identity.GetCurve` now returns `(elliptic.Curve, error)` for the same
  reason (its sole caller, in tests, is updated). `pkg/ca`'s CRL/AIA
  importers (`ImportDistributionCRLs`, `ImportIssuingCAs`) and cross-signing
  readers (`CrossSignedPEM`, `getXSignedCertificates`,
  `readCrossSignedCertificate`) now join HTTP response body and object-store
  reader Close failures into their returned error with `errors.Join` instead
  of dropping them, and `IssueCertificateWithProfile` now fails instead of
  returning an `IssuedCertificate` with a silently empty `CACertificatePEM`
  when `CABundle` errors. The cross-sign-aware TLS/trust-pool builders
  (`TLSBundleWithCrossSigner`, `TLSConfigWithXSigner`,
  `TrustedRootCertPoolWithXSigner`, `TrustedIntermediateCertPoolWithXSigner`)
  are updated in the same change so a Close-only failure from the above no
  longer discards certificates that were already read and parsed
  successfully; the error is now logged via `slog.Warn` instead of silently
  gating certificate inclusion. In `pkg/ssh/agent`, `serveListener`'s
  listener/connection Close errors and each connection handler's
  `ServeAgent` error are now recorded on a new `tracker.err()` accumulator
  (filtering `io.EOF`/`net.ErrClosed`, the documented "already closed"
  shapes) and surfaced through `Serve`'s return and a new `Session.Err()`
  accessor; `StartSession`'s work-directory rollback failures are now
  joined into the returned error instead of discarded. `pkg/ssh/session`
  (`Run`/`Shell`/`Upload`) and `pkg/ssh/console` (`open`, `Dial`) now close
  their `*ssh.Session`/`*ssh.Client` through shared helpers
  (`closeSession`/`wireCancellation` and `closeSessionOnError`
  respectively) that join a genuine Close failure into the returned error
  while filtering `io.EOF` per x/crypto/ssh's documented "already closed"
  convention; `pkg/ssh/session/dial.go`'s TCP/handshake rollback Close
  errors are joined the same way. `pkg/ssh/connect`'s `cleanupDir` now
  returns its `os.RemoveAll` error, joined into `Start`'s `*LaunchError` on
  every setup-failure path and, for the teardown path (`Stop`/
  `SyncAndStop`, including the background reaper), recorded on a new
  `Session.Err()` accessor and joined into `SyncAndStop`'s own return.
  `pkg/ssh/profile`'s `RenameFolder`/`DeleteFolder` now propagate a
  `RemoveFolder` failure instead of leaving an inconsistent folder-marker
  state behind while reporting success. `pkg/ssh/local.DialAgent` and
  best-effort notification/mirroring writes in `pkg/ssh/console`
  (hostkey notify/confirm frames, PTY resize, `CloseWrite`, environment
  variables, known_hosts mirroring) now join or log rather than drop their
  errors. `pem.Decode`'s discarded "rest" return, `hash.Hash.Write`/
  `bytes.Buffer.Write`/`strings.Builder.Write` (which the standard library
  documents as never failing), and boolean (non-`error`) discards such as
  `tracker.joinWithin` are left as-is: they were never errors being
  silenced. Every behavior change has a paired success/error test using the
  package's existing test doubles (go-xkms#701).
