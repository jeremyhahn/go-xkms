- **The last ignored errors in library and CLI code are handled, and the
  bugs they were hiding are fixed.**
  - The REST `page`/`page_size` query parameters now return 400 when they
    are not numeric. All eight paged REST list endpoints (crypto backends,
    keys, certificates, custodian groups, shares, tenants, FROST keys, PIV
    slots) now parse pagination through the one shared
    `transport.PageRequestFromQuery` implementation
    (`pkg/api/transport/pagination.go`) instead of a REST-local
    `parsePageRequest` duplicate that built its errors with `fmt.Errorf`;
    the shared function's `*InvalidPaginationParamError` is a typed error.
    `sort_order` now also accepts the `asc`/`desc` string form the REST API
    and its TypeScript SDK send on the wire, in addition to the existing
    integer form, so the two implementations agree on what is valid. The
    query parameters and the 400 are documented in the `api.md` of every
    affected feature folder (crypto-backends, key-management,
    certificate-authority, share-custody, frost-threshold-signing,
    piv-smartcard, multi-tenancy); three of those folders
    (piv-smartcard, multi-tenancy, share-custody) previously said their
    lists were unpaged or "returned whole", which stopped being true once
    pagination landed on those handlers. The TypeScript SDK's `PageQuery`
    doc comment now says `page`/`page_size` must be integers.
  - `ExecHandler` (`xkey oidc ... --output exec --pass-json`) no longer
    reports a command that exited 0 as failed. A child that exits without
    reading all of a large (>64 KiB) JSON payload on stdin makes the
    write's goroutine observe `EPIPE`, or the following `Close` observe
    `os.ErrClosed`; both are now filtered out as benign instead of being
    joined into the result.
  - `xkey oidc stop` no longer reports a PID file that was never created as
    a removal failure; only a removal failure other than `os.ErrNotExist`
    is surfaced.
  - `xkey barrier`'s PCR-policy auto-unseal no longer turns a successful
    auto-unseal into a failure when closing the PCR policy store
    afterward fails; that failure is logged instead, matching the
    documented `(true, closer, nil)` success contract.
  - The OIDC client bounds every token-endpoint response read to 1 MiB
    (`io.LimitReader`) instead of an unbounded `io.ReadAll`, and a
    non-OAuth2 error body is truncated to 256 bytes, stripped of
    non-printable characters, and prefixed with the status code and
    content type before it reaches `TokenRequestError.Description`.
  - `xkey piv status` no longer turns a failure closing PIV storage into a
    command failure; that command's job is to report status ("don't fail,
    just report status" is already its convention for every other error in
    it), so the close failure is now warned on the output writer instead,
    matching `xkey migrate`'s existing warning convention.
  - Malformed share, custodian and tenant timestamps on the gRPC and unix
    transports are logged instead of silently becoming zero.
  - `xkey oath generate` warns when it cannot persist an advanced HOTP
    counter, so the counter can no longer drift silently.
  - The `e2eprobe` interop probe no longer treats an undecodable response as
    an empty success.

  Across the root module and xkey, cleanup errors are joined into the
  returned error, or logged where the function has no error channel. The
  join happens only when Close actually fails, so bare sentinel returns keep
  their identity -- including at the sites a follow-up review found still
  joining unconditionally (`barrier_init.go`, `barrier_seal.go`,
  `barrier_unseal.go`, `secret_service.go`, `device_pair.go`, `barrier.go`,
  `barrier_auto_unseal.go`, `xkey/pkg/oidc/callback.go`,
  `xkey/pkg/keyboard/keyboard.go`, `xkey/pkg/nativemsg/pairing.go`), which
  are now guarded the same way. What remains is CLI output writes,
  flag-binding calls, read-side body closes, and discards of non-error
  values. (go-xkms#701)
