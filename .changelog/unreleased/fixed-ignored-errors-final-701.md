- **The last ignored errors in library and CLI code are handled, and four
  bugs they were hiding are fixed.**
  - The REST `page`/`page_size` query parameters now return 400 when they are
    not numeric. `parsePageRequest` used to treat them as unpaginated.
  - Malformed share, custodian and tenant timestamps on the gRPC and unix
    transports are logged instead of silently becoming zero.
  - `xkey oath generate` warns when it cannot persist an advanced HOTP
    counter, so the counter can no longer drift silently.
  - The `e2eprobe` interop probe no longer treats an undecodable response as
    an empty success.

  Across the root module and xkey, cleanup errors are joined into the
  returned error, or logged where the function has no error channel. The
  join happens only when Close actually fails, so bare sentinel returns keep
  their identity. What remains is CLI output writes, flag-binding calls,
  read-side body closes, and discards of non-error values. (go-xkms#701)
