- **Every MCP handler classifies malformed params as Invalid params, and a
  missing key, backend, or user now reaches the caller as Not found instead
  of an internal fault.** Roughly thirty `pkg/api/mcp/handlers*.go` handlers
  decoded `req.Params` with a bare `json.Unmarshal` and returned the failure
  as a plain `*errs.Wrapped` — not a `*KeyOpError` — so `InvokeMethod` and
  the unified server's `mcpToolHandler` could not classify it and it reached
  the caller as `wire.CodeInternal` regardless of the actual fault. Every
  handler now decodes through the shared `decodeParams` helper
  (`pkg/api/mcp/utils.go`), which always returns a
  `*KeyOpError{Code: ErrCodeInvalidParams}` (`-32602`); `ssh.*`'s own
  `json.Unmarshal` + `mapSSHError` path is unchanged, since it already
  produced the same outcome through SSH's richer NotFound/Duplicate/Mismatch
  vocabulary. `handlers_user.go`'s `unmarshalUserParams` — a second,
  parallel decode helper that returned an unclassified error for every
  `user.*` method — is deleted outright in favor of `decodeParams`.
  `xkms.ErrKeyNotFound` and `xkms.ErrBackendNotFound`
  (`errors_keyops.go`'s `keyOpSentinelCodes`) and a
  `*qrdbsdk.UserNotFoundError` reached through a user lookup
  (`handlers_user.go`'s new `mapUserError`) now classify onto
  `sdkssh.JSONRPCCodeNotFound` — the reserved-range JSON-RPC code this
  package's SSH sub-system already defined for the identical `wire.CodeNotFound`
  outcome (`sdk/go/client/ssh/mcp_status.go`) — instead of falling through to
  `ErrCodeInternalError`, matching go-qrdb's own NotFound classification of
  `UserNotFoundError` across its gRPC, QUIC, and MCP-wire transports ("lower
  layers win"). The shared key-lookup helpers `keyByCN`, `requireKey`,
  `findKeyByCN`, and `findKeyInBackend` (`handlers.go`) are fixed at the
  source so every handler that calls them (`getKey`, `deleteKey`,
  `listKeys`, `sign`, `verify`, `encrypt`, `decrypt`, `asymmetricEncrypt`,
  `asymmetricDecrypt`, `getTLSCertificate`, `exportKey`, `wrapKey`,
  `unwrapKey`) inherits the fix without its own change. The SDK's reverse
  table (`pkg/api/transport/mcp/status.go`'s `wireCodeToRPCCode`) and the
  unified server's forward table (`pkg/apimodule/module_mcp_errors.go`'s
  `keyOpCodeToWire`, which already carried the SSH row) are updated to
  match. Proven end to end: `TestEveryHandler_MalformedParamsAreInvalidParams`
  (`pkg/api/mcp/malformed_params_sweep_test.go`) drives every entry of the
  JSON-RPC method registry with unparsable JSON and asserts `-32602`, so a
  future handler that stops decoding through `decodeParams` fails that test
  by name; `TestE2E_MissingKeyIsClassifiedNotFound`
  (`pkg/api/transport/mcp/transport_e2e_server_test.go`) drives a missing
  key through the real unified-server dispatch path and the real SDK client
  and asserts it arrives as `sdkssh.JSONRPCCodeNotFound` /
  `wire.CodeNotFound` (go-xkms#774, #814).
