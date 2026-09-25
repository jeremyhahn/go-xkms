- **PCR policy management now works over every network transport, not just
  REST.** `PolicyCreate`, `PolicyGet`, `PolicyList`, `PolicyDelete`,
  `PolicyRefresh`, `PolicyVerify` and `PolicyExport` were `ErrNotSupported`
  one-liners on the gRPC, Unix, QUIC and MCP client transports, and
  `PasswordStoreSetAccessMode` was likewise stubbed on gRPC and Unix
  (go-xkms#691); `xkmsctl policy` and any SDK caller not on REST failed on
  every one of those verbs. All seven Policy RPCs and messages were added
  to `pkg/api/grpc/proto/xkmsv1/xkms.proto` and regenerated; the gRPC
  service (and, over the same generated client, Unix) delegates to
  `pkg/xkms.XKMSService`'s existing `PolicyServicer`; QUIC (HTTP/3 on the
  REST router) and the REST client transport translate REST's own wire
  shapes via new `pkg/api/rest/wire` PCR Policy types; MCP gained
  `policy.*` tool handlers and dispatch-table entries. Authorization is a
  new `policy:*` permission family (`pkg/auth.ResourcePolicy`,
  `pkg/apimodule/module_scopes.go`) mirrored one-for-one across REST's
  route table, the gRPC proto's `(qrdb.v1.permission)` options, and MCP's
  `methodPermissions` — go-qrdb's canonical registry does not declare a
  policy resource, so xkms mints and scopes it itself, the way it already
  does for `bootstrap:read`. `PasswordStoreSetAccessMode` on gRPC/Unix
  gates on `passwords:write`, matching its `PasswordUpdate` sibling.
  `pkg/api/keyops_parity_test` gained `TestPolicy_RESTAndGRPCAgree` and
  `TestPolicy_ValidationAgrees`, driving one shared `xkms.XKMSService`
  through both transports so a future regression to a stub fails a test
  rather than shipping. The USB transport (a Noise-encrypted JSON-RPC peer
  to the xkey Android companion app, not xkmsd, with no TPM) and the four
  `pkg/escrow` RPCs (a separate open question, go-xkms#692) are
  unaffected. Files: `pkg/api/grpc/proto/xkmsv1/xkms.proto`,
  `pkg/api/grpc/service_policy.go`, `pkg/api/grpc/service_password.go`,
  `pkg/api/transport/{grpc,unix,quic,rest,mcp}/transport.go`,
  `pkg/api/mcp/handlers_policy.go`, `pkg/api/mcp/authz.go`,
  `pkg/api/mcp/server.go`, `pkg/api/rest/wire/types.go`,
  `pkg/auth/permissions.go`, `pkg/apimodule/module_scopes.go`,
  `internal/authzscan/authzscan.go`,
  `pkg/api/keyops_parity_test/policy_parity_test.go`,
  `test/integration/api/commands/commands.go`.
