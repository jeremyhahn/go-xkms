- **Closure-wrapped `_ = x.Close()`/`Rollback()`/`Sync()` discards outside
  `pkg/acme` no longer silently drop a close failure.** Read-side closes that
  run after the caller's result is already decided (HTTP response bodies in
  `pkg/auth/oidc.go`, `pkg/trust/fetcher`, `pkg/trust/clusterca`,
  `pkg/escrow/xkms`, `pkg/webauthn/client`, `pkg/api/transport/unix`,
  `pkg/tpm2`, `sdk/go/login.go`, `sdk/go/client/ssh`, and the
  `sdk/go/acme/transport` family via a new shared `transport.CloseResponseBody`
  helper; object-store blob readers in `pkg/ca`; discarded duplicate/loser
  resources in `pkg/staticpw`, `pkg/escrow/kmip`, `pkg/xkms/piv_manager`;
  file/connection cleanup in `pkg/ssh/console`, `pkg/webui`,
  `pkg/pkcs11/module`, `pkg/crypto/spki`, `pkg/xkeysigner`,
  `pkg/api/transport/usb`, `pkg/api/transport/grpc`, `pkg/seal/autodetect`)
  now log the failure at `slog.Debug` through the package's existing logger
  (or a small package-local helper where several sites in a file shared the
  same shape, following #866's convention) instead of dropping it. Cleanup
  after a primary error (`pkg/api/unix/grpc_server.go`,
  `pkg/server/loopback`, `pkg/server/platform_store.go`,
  `pkg/webauthn/client/hardware_adapter.go`,
  `sdk/go/client/ssh/mcp.go`, `sdk/go/acme/transport/grpc`) now joins the
  close error into the returned error with `errors.Join` instead of
  discarding it. `cmd/xkmsctl` had roughly 130 identical
  `defer func() { _ = cl.Close() }()`-shaped sites across every subcommand
  file; they now share one `closeQuiet(io.Closer)` helper in `config.go`
  that logs at debug. `cmd/xkmsd`'s two rollback-on-failed-startup closes
  (the ACME audit logger, the init ceremony's FIDO2 handler) now log via the
  caller's `*slog.Logger` at `Warn`. `pkg/ssh/known_hosts/export.go`'s
  read-only known_hosts import close and `sdk/go/xkey_auth.go`'s
  `xkeysigner.Signer.Close` (which never returns a non-nil error) are left
  as documented discards; `sdk/go/acme/http01_responder.go`'s matching text
  is a doc comment, not code. `sdk/go/acme/examples/{acme,admin}/main.go`
  now log a close failure via the example's own `log.Printf` rather than
  discard it (go-xkms#876).
