- **The MCP client transport now calls the JSON-RPC method names the real
  MCP server actually registers.** The client sent `xkms.passwordAdd`,
  `xkms.passwordGet`, `xkms.passwordList`, `xkms.passwordUpdate`,
  `xkms.passwordDelete`, `xkms.passwordStoreUnlock`, `xkms.passwordStoreLock`,
  `xkms.passwordStoreStatus`, and `xkms.passwordGenerate`
  (`pkg/api/transport/mcp/transport.go`) while the server
  (`pkg/api/mcp/server.go`) registered the `password.*` family — every
  password-vault call over MCP failed with "method not found". Renamed the
  client to `password.add`/`get`/`list`/`update`/`delete`/`unlock`/`lock`/
  `status`/`generate`, the names both `docs/password-vault/api.md` and the
  server already used (#762). Also fixed two stale generic-path entries
  (`init.claim-share` split into the real `init.claimShareBegin`/
  `init.claimShareComplete`, matching the two-phase ceremony) and removed
  three dead `barrier.shamir*` path mappings with no REST route or server
  handler behind them.
- **Added the missing `password.setAccessMode` MCP handler.** The client
  called `xkms.passwordStoreSetAccessMode`, for which the server had no
  handler or `methodPermissions` entry at all (#753). New
  `Server.handlePasswordSetAccessMode` (`pkg/api/mcp/handlers_password.go`)
  delegates to `XKMSService.PasswordStoreSetAccessMode`, the same servicer
  REST's `SetAccessModeHandler` calls, gated on `passwords:write` — matching
  the `passwords:write` action every other password-vault write method
  already requires. Renamed the client call to `password.setAccessMode` to
  match.
- **Added the missing `xkms.getBackend` MCP handler.** `docs/key-management/
  api.md` and `docs/crypto-backends/api.md` already documented this method
  with a `backends:read` permission, but no handler existed; the client's
  `GetBackend` call has always failed with "method not found". New
  `Server.handleGetBackend` delegates to `XKMSService.GetBackend`, the same
  `transport.XKMSServicer` method the embedded transport calls directly.
- Added `TestClientMethods_HaveServerHandlers`
  (`pkg/api/transport/mcp/method_parity_test.go`), the regression guard for
  all of the above: it parses the client transport's source for every
  JSON-RPC method name it can send (`rpcCall` call sites, `methodMapping`,
  `dynamicPatterns`) and asserts each one is either dispatchable on the real
  server (`xkmsmcp.ModuleMethods()`) or is a documented, tracked gap
  (`knownServerGaps`, cited against the feature docs: PIN management,
  custodian groups, tenant administration, and KDF key derivation are all
  intentionally absent from MCP today). `TestMethodPermissions_
  CoverEveryDispatchableMethod` (pre-existing) already proves every
  dispatchable server method carries an authorization entry. Added real,
  in-process round-trip tests (`pkg/apimodule/module_mcp_password_roundtrip_
  test.go`, `module_mcp_getbackend_roundtrip_test.go`) that drive the
  production client transport against a real `mcp-go` server built from the
  real `Module.RegisterMCP` wiring.
