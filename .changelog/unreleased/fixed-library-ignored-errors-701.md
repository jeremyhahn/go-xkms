- **Library code no longer discards errors with `_ =`.** Two correctness
  bugs are fixed: `pkg/api/mcp` (`handlers.go`, `handlers_ssh.go`) silently
  treated malformed JSON-RPC params as an absent, all-zero-value request on
  seven `listBackends`/`listKeys`/`listCerts`/`ssh.*.list` handlers instead
  of rejecting them; a caller with a typo in their params object got a
  confusingly successful, unfiltered response. They now report Invalid
  params (-32602) through a new shared `decodeParams` helper (or, for the
  SSH handlers, the package's existing `SSHInvalidParamsError` wrapped in
  the same `*KeyOpError{Code: ErrCodeInvalidParams}`). `transport.PageRequestFromQuery`
  (`pkg/api/transport/pagination.go`) silently parsed an unparsable
  `page`/`page_size`/`sort_order` query parameter to zero, turning a
  caller's typo into an unpaginated "return everything" request; it now
  returns `(PageRequest, error)` and reports a new
  `*InvalidPaginationParamError`, with its one caller
  (`pkg/api/rest/handlers_team.go`) updated to answer 400. `pkg/webauthn/qrdb_userstore.go`
  had four sites where a failed credential-index read was treated as an
  empty index and then *persisted*, which could silently wipe every other
  credential a user has from the index on `Save`, `Delete`, or delete every
  credential blob without updating the index on `DeleteByUserID`; each now
  propagates the read failure instead, and per-credential KV-delete
  failures during best-effort cleanup are now joined with `errors.Join`
  instead of discarded. `pkg/acme/admin/service.go`'s `GetStatus` now
  distinguishes `ca.ErrIntermediateNotFound` (a pure-root CA, expected) from
  any other `TrustedIntermediate` failure (now reported), and `GetStats`
  now fails instead of silently under-counting an account's orders when
  `ForEachPage` errors. `pkg/pkcs11/module`'s ~60
  `SessionManager.FinalizeOperationType` cleanup calls (C_Finalize-style
  teardown that runs after a Sign/Verify/Encrypt/Decrypt call's CK_RV is
  already decided, so it cannot itself fail the call) now route through one
  new `Module.finalizeOperationType` helper that records a failure via the
  existing `logStorageError`/`LastStorageError` mechanism instead of
  discarding it; its 11 `ObjectManager.DestroyObject` rollback-cleanup call
  sites (key-pair generation and key unwrap) now follow the same
  log-on-failure idiom already used by their neighboring, previously-fixed
  call sites in the same functions. Each fix has a success test and a
  failure-injection test proving the previously-discarded error now
  surfaces. `pkg/api/transport/grpc/transport.go` and
  `pkg/api/transport/unix/transport.go` also discard `time.Parse` errors
  (10 sites) when converting server-generated RFC3339 timestamps on
  display-only response metadata (share/tenant/custodian-group
  `CreatedAt`/`UpdatedAt`); these are left as-is pending owner review —
  each already carries a doc comment stating the degrade-to-zero-time
  design intentionally, the values are server-generated (not attacker
  input), and the conversion functions are called from 15+ sites across two
  large files including inside slice-building loops, so changing their
  signature to return an error is a larger, riskier change than this issue's
  scope (go-xkms#701). Files: `pkg/api/mcp/utils.go`,
  `pkg/api/mcp/handlers.go`, `pkg/api/mcp/handlers_ssh.go`,
  `pkg/api/transport/pagination.go`, `pkg/api/rest/handlers_team.go`,
  `pkg/webauthn/qrdb_userstore.go`, `pkg/acme/admin/service.go`,
  `pkg/pkcs11/module/module.go`, `pkg/pkcs11/module/module_keygen_quantum.go`,
  plus their tests.
