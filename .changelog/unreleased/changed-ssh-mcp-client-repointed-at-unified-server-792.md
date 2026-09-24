- **The SDK's `mcp://`/`mcps://` SSH client now dials the unified qrdb MCP
  server instead of a raw JSON-RPC-over-TCP plane that had no server
  counterpart.** `sdk/go/client/ssh/mcp.go`'s `NewMCP` previously line-framed
  JSON-RPC 2.0 requests over a raw `net.Conn`, speaking a protocol
  `pkg/api/mcp/server.go` documents as retired when the unified server
  replaced it — `cmd/xkmsd` and `pkg/server` never ran a listener for it, so
  every real `mcp://` dial failed, and the SDK's own tests only ever
  exercised a self-contained fake server (#792). The unified server already
  registers `ssh.keys.*`/`ssh.knownHosts.*`/`ssh.authorizedKeys.*` as real
  MCP tools (`pkg/apimodule.RegisterMCP`, via `pkg/api/mcp.ModuleMethods`),
  so `NewMCP` now speaks the same MCP Streamable HTTP tool-call framing
  `pkg/api/transport/mcp.Transport` uses to reach that server. The
  `Client`/`MCPOptions` surface is unchanged; only the wire protocol
  underneath it moved.
- **Added `pkg/mcptool`**, the shared connection/handshake/tool-call
  machinery both `pkg/api/transport/mcp.Transport` and the SSH SDK's MCP
  client now build on, instead of the SSH client keeping a second
  hand-rolled MCP client. It lives outside `pkg/api/transport/mcp` because
  that package imports `pkg/api/mcp` for its own error-code classification,
  and `pkg/api/mcp`'s `Server` holds an `sdk/go/client/ssh.Client` for its
  SSH sub-system (`Config.SSHClient`) — importing `pkg/api/transport/mcp`
  from the SSH SDK package directly would cycle back through it.
  `pkg/api/mcp.ToolName` now delegates to `pkg/mcptool.ToolName`, the single
  canonical implementation of the `xkms_`-prefixed tool-naming convention.
  Error classification is envelope-only throughout: `pkg/mcptool.Client`
  decodes go-qrdb's `wire.ErrorEnvelope` directly (there is no
  keyword/regex fallback anywhere in this path, matching #797's removal of
  that pattern from `pkg/api/transport/mcp`); `RPCError` now carries both
  `WireCode` (go-qrdb's raw classification) and `Code` (an optional
  caller-supplied translation onto a legacy numeric vocabulary, via the new
  `ErrorClassifier`/`WithErrorClassifier`). `pkg/api/transport/mcp`'s own
  classification (`status.go`) is now a thin `wireCodeToRPCCode`-backed
  adapter passed to `pkg/mcptool` as that classifier; its behavior for the
  `xkms.*` method family is unchanged.
- **Added `mapSSHError`** (`pkg/api/mcp/errors_ssh.go`), the SSH
  sub-system's counterpart to `mapKeyOpError`. Every `ssh.*` handler
  (`handlers_ssh.go`) previously returned its underlying error unwrapped, so
  `pkg/apimodule`'s `mcpToolHandler` never matched it as a `*KeyOpError` and
  **every** SSH failure — not-found, duplicate, host-key mismatch, bad
  input, whatever — reached MCP callers as the same generic "xkms: internal
  error", with the actual detail discarded. `mapSSHError` classifies every
  SSH domain error (`pkg/ssh/keys`, `pkg/ssh/known_hosts`,
  `pkg/ssh/authorized`, and the SDK's own validation errors) onto the eight
  JSON-RPC codes `pkg/api/mcp/types.go` already declares. That vocabulary
  has no dedicated NotFound or AlreadyExists member, so a resource not
  found, a non-idempotent duplicate, and a host-key mismatch all land on
  `ErrCodeInvalidParams` — the same bucket `wireCodeToRPCCode` already uses
  for `wire.CodeNotFound` — rather than on three different codes; this is a
  documented limitation, verified end to end
  (`pkg/apimodule/module_mcp_ssh_roundtrip_test.go`'s `TestSSHRoundTrip_
  NotFound`/`TestSSHRoundTrip_Mismatch`), not an assumption.
- **The SSH SDK's MCP client reconstructs its own typed errors from the
  server's classification.** `sdk/go/client/ssh/mcp.go`'s `classifyMCPError`
  turns a failed call's `*mcptool.RPCError.WireCode` into
  `*AuthError`, `*NotImplementedError`, `*ServerError`, or
  `*InvalidRequestError` — mirroring how the REST transport's
  `decodeErrorResponse` reconstructs the same types from an HTTP status.
  `wire.CodeNotFound`/`wire.CodeAlreadyExists` decode to
  `*NotFoundError`/`*DuplicateError` for forward compatibility with a future,
  finer-grained `mapSSHError`, even though nothing emits those codes today.
- Real end-to-end coverage: `pkg/apimodule/module_mcp_ssh_roundtrip_test.go`
  drives the production `sdk/go/client/ssh` MCP client against a real
  `mcp-go` server built from the real `Module.RegisterMCP` wiring and a real
  embedded SSH backend, including the not-found and host-key-mismatch cases
  above. `sdk/go/client/ssh/mcp_test.go` and `mcp_dial_test.go` were
  rewritten to a real in-process `mcp-go` Streamable HTTP server (the same
  pattern `pkg/api/transport/mcp`'s and `pkg/mcptool`'s own tests use) that
  answers coded `wire.ErrorEnvelope` failures exactly as the real server
  does, replacing the previous raw-TCP fake server.
