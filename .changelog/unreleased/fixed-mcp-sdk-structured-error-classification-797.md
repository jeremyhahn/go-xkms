- **BREAKING: the xkms SDK's MCP transport classifies a failed tool call by
  go-qrdb's wire error code, never by matching keywords in the error text.**
  `pkg/api/transport/mcp.Transport.rpcCall` used to run every failing tool
  result's message through `toolErrorCode`, a best-effort `strings.Contains`
  table, and through `rpcErrorPattern`, a regex that recovered a legacy
  "`JSON-RPC error <code>: <message>`" code embedded in prose — the same
  fail-open classification go-qrdb deleted from its own SDK client
  (go-qrdb#438) after #791 taught the unified server's real MCP tool surface
  to stamp a `wire.ErrorEnvelope` onto every failing xkms tool result's
  `structuredContent`. Both mechanisms are deleted outright, with no text
  fallback: `classifyToolError` (`status.go`) now decodes the envelope with
  `wire.DecodeErrorPayload` and maps its `wire.Code` onto the JSON-RPC error
  codes `*RPCError.Code` has always carried (`CodeUnauthenticated` →
  `ErrCodeUnauthorized`, `CodePermissionDenied` → `ErrCodeForbidden`,
  `CodeNotFound`/`CodeInvalidArgument` → `ErrCodeInvalidParams`,
  `CodeUnavailable` → `ErrCodeServiceUnavailable`, `CodeUnimplemented` →
  `ErrCodeMethodNotFound`, everything else including `CodeInternal` →
  `ErrCodeInternalError`). A failing tool result carrying no envelope at all
  is a new typed error, `*EnvelopeMissingError` — a protocol error, since the
  unified server always stamps one onto a failing xkms tool result, so a
  response with none did not come from that contract. Proven end-to-end
  through the real unified-server dispatch path
  (`pkg/api/transport/mcp/transport_e2e_server_test.go`, reusing
  `pkg/apimodule.RegisterMCP` over mcp-go's in-process transport): a
  capability boundary reaches the caller as `ErrCodeMethodNotFound`, a
  validation failure as `ErrCodeInvalidParams`, and an unregistered tenant as
  `ErrCodeForbidden`; a `wire.CodeNotFound` envelope (no current server code
  path emits one, but the client no longer assumes any never will) is also
  classified `ErrCodeInvalidParams`, and a message carrying a classifier
  trigger word under an unrelated code is classified by the code, not the
  word (go-xkms#797).
