- **The MCP transport's WebAuthn registration and authentication methods are now a documented, typed exclusion rather than a transitional stub (#193).**
  `pkg/api/transport/mcp.Transport`'s `BeginRegistration`, `FinishRegistration`,
  `BeginAuthentication` and `FinishAuthentication` returned the generic
  `ErrNotSupported`, which read as "not implemented yet." Owner ruling
  2026-09-21 (option C) settled it as a named exclusion: an agent-facing
  tool-call surface must not mint sessions or enrol credentials, and MCP
  holds no identity-ceremony state. The four methods now return the typed
  `ErrIdentityCeremonyExcluded` (re-exported unchanged by
  `sdk/go/transport/mcp`), and `pkg/api/mcp.ModuleMethods`, the MCP tool
  capability surface, never lists a tool for them, so a client can discover
  the exclusion without calling and failing. Documented in
  `docs/webauthn/api.md` §Capability matrix, `docs/webauthn/engineering.md`
  §Error semantics, and `docs/key-management/api.md` §"How the six
  transports are shaped".
