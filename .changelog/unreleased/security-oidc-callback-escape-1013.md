- **xkey's OIDC callback page no longer renders the provider's error as
  HTML.**
  The CLI's loopback callback page wrote the `error` and `error_description`
  query parameters into its HTML unescaped, so anyone able to steer the
  browser to the callback URL while a login was pending (a hostile IdP, a
  crafted link) could inject markup or script into the local callback
  origin. Every callback page (CLI, GUI and `xkey oidc aws`) is now rendered
  by one function, `oidc.WriteCallbackPage`, through `html/template`, and is
  served with `Content-Type: text/html; charset=utf-8`,
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src
  'none'; style-src 'unsafe-inline'` and `Referrer-Policy: no-referrer`.
  Tests send a `<script>` / `"><img onerror>` redirect to each of the three
  handlers and assert the escaped output and the headers. (go-xkms#1013)
