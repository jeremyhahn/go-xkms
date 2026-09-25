- **xkey no longer passes identity-provider text to the terminal or logs
  as raw control sequences.**
  A hostile or compromised identity provider could put ANSI/OSC escape
  sequences in the callback's `error` and `error_description`, in a
  token-endpoint error, or in an ID-token claim. xkey printed and logged
  that text unchanged, so the provider could clear the screen, spoof a
  prompt or write the clipboard through OSC 52. All such text now passes
  through one function, `oidc.SanitizeProviderText`, before it reaches a
  terminal or a log. The function removes every ESC-introduced and 8-bit C1
  sequence whole and drops the remaining C0/C1 controls and bidi overrides.
  It turns line breaks into spaces, so a provider cannot forge a log line,
  and it cuts the text to 512 bytes, marking the cut with `...[truncated]`.
  It is applied to the CLI, GUI and `xkey oidc aws` callback errors, to
  `oidc.TokenRequestError.Error()`, to the AWS token-request error, to the
  GUI's refresh error, and to the claims and AWS access key ID that
  `xkey oidc login`, `xkey oidc token` and `xkey oidc aws login` print.
  Tests send an OSC 52 + `ESC[2J` + 8-bit CSI + NUL payload through every
  one of these paths and assert that it comes out as plain text. A fuzz
  target checks that the output is inert, bounded and idempotent.
  (go-xkms#1015)
