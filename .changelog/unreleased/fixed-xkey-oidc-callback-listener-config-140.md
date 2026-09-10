- **xkey: the OIDC and AWS login callback listeners bind a configured host and port (#140, items 7 and 13).**
  `xkey oidc login` listened on `":"+port`, every interface, for a browser
  redirect that only ever arrives on loopback, and `xkey oidc aws` hard-coded
  port 8085 with no flag, variable or config path. The xkey config gains an
  `oidc` section (`callback_host`, default `localhost`, which binds both
  loopback families since the browser may resolve the redirect host to either;
  `callback_port`, default 8085; `XKEY_OIDC_CALLBACK_HOST` /
  `XKEY_OIDC_CALLBACK_PORT`), and both commands gain `--callback-host` and
  `--callback-port` (held to 1-65535). The default redirect URL follows the
  callback host, so the browser is always sent where the listener is. The
  listener binds the callback host on the redirect
  URL's port, so an explicit `--redirect-url` or a saved provider's keeps the
  port registered with the provider; the default redirect URLs and the AWS
  refresh worker take the port from configuration. AWS's redirect host is
  fixed at `127.0.0.1`, so its listener serves `127.0.0.1`. The OIDC listener
  binds addresses that serve the redirect URL's host (the loopback pair for
  `localhost`, an IP literal itself, the configured address for another
  name, every interface for the empty host); a callback host that cannot
  serve the redirect host is a typed `OIDCCallbackHostError` before any
  browser opens rather than a five-minute timeout, and a redirect URL the
  listener cannot serve, an https one included (the listener is plain http),
  is a typed `OIDCRedirectURLError`.
