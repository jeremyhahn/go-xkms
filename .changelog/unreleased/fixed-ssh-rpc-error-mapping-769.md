- **gRPC and MCP now report the same NotFound/AlreadyExists/Mismatch
  semantics REST already reported for every SSH key, known_hosts, and
  authorized_keys store error, instead of collapsing almost all of them to a
  generic Internal fault.** `pkg/api/grpc`'s `sshStatus` matched only
  `*sdkssh.NotFoundError` by concrete type; `*pkgkeys.KeyNotFoundError` and
  its `known_hosts`/`authorized` siblings (`NotFoundError`, `DuplicateError`,
  `MismatchError`) fell through to `codes.Internal`, and the SSH SDK's MCP
  client (`sdk/go/client/ssh/mcp.go`) collapsed every server error to a bare
  `*ProtocolError` regardless of its JSON-RPC code. `sdk/go/client/ssh` gains
  a single shared classification (`classify`, unexported) that
  `HTTPStatusForError` (REST, unchanged behavior), the new
  `GRPCCodeForError`, and the new `JSONRPCCodeForError` all derive their
  wire-level code from, so the three transports cannot drift from each
  other: NotFound -> 404 / `codes.NotFound` / -32001, a duplicate Add ->
  409 / `codes.AlreadyExists` / -32005, and a known_hosts mismatch (a
  MITM indicator) -> 409 / `codes.FailedPrecondition` / -32006. `pkg/api/
  grpc`'s `sshStatus` and the SSH SDK's gRPC client (`mapGRPCError`, which
  previously had no `codes.AlreadyExists` decode branch at all) both route
  through the shared table; `pkg/api/mcp` gains `mapSSHError` (mirroring the
  existing `mapKeyOpError` pattern for the other key handlers) so every SSH
  handler assigns the right `*KeyOpError.Code`; and the SDK's MCP client
  gains `mcpErrorFromResponse`, which reconstructs the typed
  `NotFoundError`/`DuplicateError`/`MismatchError` (with full
  Resource/Host/Expected/Received fidelity when the server's JSON-RPC error
  carries a `data` envelope, mirroring REST's `errorEnvelope`) instead of
  wrapping every failure in `*ProtocolError`. An error none of these tables
  recognize still reports Internal on every transport; gRPC additionally
  never echoes that error's own message onto the wire (a fixed `"ssh:
  internal error"` instead), since an unclassified error may wrap
  storage-backend detail such as a filesystem path. (go-xkms#769)
