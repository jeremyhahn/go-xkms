# Error Conventions

go-xkms does not construct errors with `fmt.Errorf`. Every error is either a
package sentinel (`errors.New` / a typed error declared in the owning package)
or one of the five reusable typed errors in `pkg/errs`. All five are
transparent to `errors.Is` / `errors.As` via `Unwrap`.

## The Five `pkg/errs` Types

| Type | Renders as | Use when |
|------|-----------|----------|
| `Message` | `<msg>` | A fixed or pre-formatted message with no cause. Pre-format with `fmt.Sprintf` when the message needs interpolation: `&errs.Message{Msg: fmt.Sprintf("key not found: %s", id)}`. |
| `Wrapped` | `<msg>: <cause>` | Adding contextual prefix to an underlying error (the replacement for `fmt.Errorf("...: %w", err)`): `&errs.Wrapped{Msg: "failed to sign", Err: err}`. |
| `Detail` | `<err>: <detail>` | Appending detail text after a sentinel so callers can still match the sentinel: `&errs.Detail{Err: ErrInvalidPEM, Detail: "empty bundle"}`. |
| `Affix` | `<prefix><cause><suffix>` | A cause embedded mid-message with text on both sides: `&errs.Affix{Prefix: "decode status: ", Err: err, Suffix: fmt.Sprintf(" (%s)", body)}`. |
| `Joined` | `<lead>: <cause>` or `<lead>: <detail>: <cause>` | Wrapping two causes at once (the replacement for a format error with two `%w` verbs), typically a sentinel plus the underlying failure. Both match through `errors.Is` / `errors.As`. |

## Rules

- **Sentinels are package-level.** Known failure conditions get a named
  `Err*` sentinel (`errors.New` or a typed error) in the owning package, not
  an inline literal at the failure site.
- **Sentinel preservation.** When adding context to a sentinel, wrap it with
  `Detail`, `Affix`, or `Joined` — never flatten it into a new string. The
  sentinel must keep matching via `errors.Is` after wrapping.
- **Message parity.** When migrating an existing error, the rendered message
  is preserved byte-for-byte; only the construction changes.
- **Tests and examples follow the same rules.** Integration tests in
  submodules that cannot import `pkg/errs` carry their own small typed-error
  file with matching build tags (see `xkey/test/integration/errors.go`).
- The only permitted `fmt.Errorf` calls in the repository are the parity
  oracles in `pkg/errs/errs_test.go`, which verify that each type renders
  identically to the format expression it replaces.
