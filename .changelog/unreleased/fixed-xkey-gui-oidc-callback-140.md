- **xkey GUI: the OIDC login callback listener binds the configured host (#140, item 8).**
  The desktop GUI's OIDC login listened on `":"+port` with `SO_REUSEADDR`,
  every interface, for a browser redirect that only arrives on loopback, and
  defaulted the redirect URL from a literal `8085`. The callback listener
  logic now lives once in `xkey/pkg/oidc` (`Callback`, `ListenAddrs`,
  `BindCallback`, `ServeCallback`), shared by the CLI and the GUI; the GUI
  service takes `oidc.callback_host` / `oidc.callback_port` from the unified
  config through `SetCallback`, binds the loopback pair for `localhost` (with
  `SO_REUSEADDR` kept), refuses a callback host that cannot serve the
  provider's redirect host before opening the browser, and, as the CLI now
  does too, answers on exactly the redirect URL's path (a literal
  comparison, never a ServeMux pattern) rather than a fixed one. A unified
  config that fails to load disables the GUI login with the cause instead of
  binding the built-in callback in place of the operator's.
