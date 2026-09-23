- **The USB transport now proxies nine Password and all six SealStore
  methods to the phone's embedded xkmsd, and the MCP transport now
  implements all eight User management methods.** Both groups previously
  returned typed `ErrNotSupported` stubs. USB's `PasswordAdd`, `PasswordGet`,
  `PasswordList`, `PasswordUpdate`, `PasswordDelete`, `PasswordStoreUnlock`,
  `PasswordStoreLock`, `PasswordStoreStatus`, `PasswordGenerate`,
  `SealStorePut`, `SealStoreGet`, `SealStoreDelete`, `SealStoreList`,
  `SealStoreReseal`, and `SealStoreStatus` now round-trip through the
  existing Noise-encrypted `Request` envelope, using the servicer's own
  method names verbatim on the wire; `PasswordStoreSetAccessMode` is left
  for go-xkms#691. MCP's `user.create`, `user.list`, `user.get`,
  `user.delete`, `user.enable`, `user.disable`, `user.bindCert`, and
  `user.listCredentials` dispatch through new handlers in
  `pkg/api/mcp/handlers_user.go`, gated by the same `users:*` RBAC actions
  REST already enforces; a malformed `params_json` reports Invalid params
  (-32602) rather than an internal error. WebAuthn/FIDO2 enrollment stays
  excluded from MCP (go-xkms#193) — unaffected by this change. Files:
  `pkg/api/transport/usb/transport.go`, `pkg/api/transport/mcp/transport.go`,
  `pkg/api/mcp/handlers_user.go`, `pkg/api/mcp/server.go`,
  `pkg/api/mcp/authz.go`, plus their tests. Fixes go-xkms#692.
