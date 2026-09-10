- **MCP "invalid backend" refusals carry a sentinel and accept configured names (#176).**
  Five handlers refused a backend name with a bare message, so a caller could
  only tell that refusal apart from any other failure by matching its text;
  and they judged the name with `types.ParseStoreType`, which refused every
  configured backend name that is not a store-type keyword. The five sites now
  resolve the name through the service's `LookupBackend` and refuse with
  `mcp.InvalidBackendError`: `errors.Is` finds `mcp.ErrInvalidBackend`, the
  service's reason (`xkms.ErrBackendNotFound`, `xkms.ErrBackendNameValidation`)
  is the cause, the message is `invalid backend: <name>: <reason>`, and the
  JSON-RPC code is invalid-params. A registered name such as `token-a` is
  accepted; an upper-case or padded spelling, which the old gate normalised
  away, is refused like everywhere else.
