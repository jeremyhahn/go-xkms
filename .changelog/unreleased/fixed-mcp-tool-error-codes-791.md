- **The unified server's real MCP tool calls now carry a classified error
  code, not just prose.** `pkg/apimodule.mcpToolHandler` — the adapter
  `RegisterMCP` wires between the mcp-go tool surface and
  `pkg/api/mcp.Server.InvokeMethod` — called only `err.Error()` on a
  dispatch failure, so every JSON-RPC code `pkg/api/mcp`'s handlers and
  gates compute (`*KeyOpError.Code` in `errors_keyops.go`, `authz.go`,
  `tenant.go`) was discarded before it reached a caller; a not-found, an
  invalid-params refusal and an internal fault were indistinguishable tool
  errors. `mcpToolHandler` now unwraps a `*KeyOpError` (`errors.As`) and
  renders it as go-qrdb's own MCP wire contract — a `structuredContent`
  `ErrorEnvelope` (`github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire`) carrying
  the classified `wire.Code`, the exact shape go-qrdb's own MCP server
  produces for its own tools and go-qrdb's own SDK client already decodes,
  adopted rather than reinvented. An `InvokeMethod` failure that is not a
  `*KeyOpError` renders as a generic, undetailed internal fault
  (`wire.CodeInternal`) instead of leaking its text. Proven end-to-end
  through a real mcp-go server and in-process client
  (`pkg/apimodule/module_mcp_errors_test.go`): an unsupported capability
  reaches the caller as `CodeUnimplemented`, a validation failure as
  `CodeInvalidArgument`, an unregistered tenant as `CodePermissionDenied`,
  and an unclassified error as a generic `CodeInternal` fault (go-xkms#791).
