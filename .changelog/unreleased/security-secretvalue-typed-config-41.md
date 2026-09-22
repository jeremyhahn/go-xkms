- **The CA identity key password and software keystore password config
  fields are now `types.SecretValue`-typed instead of plain `string`, so the
  four `SecretValue.String()` call sites this repo carried — each suppressed
  with a per-line `//nolint:staticcheck // go-xkms#41` — are gone along with
  their directives** (#41, #133). `SecretValue.String()` copies a resolved
  secret into an immutable, unwipeable Go string on the GC heap; the two
  production sites (`pkg/server/server.go`, resolving a CA identity's
  per-key and identity-wide software keystore passwords) wrote that copy
  into a plain `string` config field that outlives the call, which is a
  custody change, not a call-site swap — the reason this issue carried
  `task:blocked` since 2026-08-20 pending an owner ruling. That ruling
  (2026-09-21, option A) is: declare the field as `SecretValue` so the
  resolved plaintext stays sealed in the field's own memguard enclave for
  the life of the config, exactly as `qrdbsecret.SecretValue`'s own doc
  comment recommends.

  `types.KeyConfig.Password` and `ca.CAKeystoreSoftwareConfig.Password`
  change from `string` to the new `types.SecretValue` alias
  (`= qrdbsecret.SecretValue`). The wire form is unchanged: both YAML and
  JSON still read and write the plain reference string (a literal password
  or a `credential://...` URI) — `SecretValue`'s own `UnmarshalYAML`/
  `UnmarshalJSON`/`MarshalYAML`/`MarshalJSON` round-trip it through `Raw`.
  The one gap that isn't covered by `SecretValue`'s own codec is that
  `pkg/config.Load` decodes through viper's mapstructure chain, not
  `yaml.v3`, so `SecretValue`'s `yaml.Unmarshaler` never runs there;
  `pkg/config/load.go` now composes a `string`→`SecretValue`
  `mapstructure.DecodeHookFunc` onto viper's default hook so a config file
  keeps loading a plain string into the field. `walkYAMLKeys` (env-key
  registration) is taught to treat `SecretValue` as a leaf rather than a
  section to descend into, so a future top-level `SecretValue` field isn't
  silently dropped from `XKMS_`-prefixed environment override the way
  descending into its unexported enclave field would drop it (today's two
  fields live inside `ca.Identity`, itself under a slice `walkYAMLKeys`
  already treats as one leaf, so this guard is defense for a shape that
  doesn't exist yet, not a fix for one that does).

  Every reader of the two fields is updated to borrow bytes at the point of
  use instead of holding a plaintext string: `types.NewPasswordFromSecretValue`
  (new) calls `SecretValue.WithBytes` to build a `types.Password` from the
  resolved enclave, falling back to treating `Raw` itself as the literal
  password only when the value was never resolved through a
  `ResolverRegistry` (`Strategy == ""`) — a `SecretValue` resolved to
  deliberately empty content (`Strategy` set, enclave empty) stays a `nil`
  password rather than reinterpreting its reference string as one.
  `KeyAttributesFromConfig` and `Identity.ToKeyAttributes` both route
  through it. `pkg/server/server.go`'s CA-init resolution loop and
  `pkg/types/types_secret.go`'s `resolveKeyConfigPasswords` move the
  registry's resolved `*SecretValue` into the field by custody transfer
  (`id.Keys[j].Password = *sv`) rather than calling `.String()`.
  `pkg/trust/clusterca/backends.go`'s `injectKeystorePassword` — a fourth,
  previously unflagged site this audit turned up, assigning a resolved
  `types.Password`'s bytes into both fields — now seals each target field
  its own enclave via the new `types.NewLiteralSecretValue`, since
  `SecretValue` is single-owner for its working life and must not be shared
  across multiple config fields as one struct copy.

  `SecretValue.String()` had no remaining caller in this repository (root,
  `sdk/go`, `xkey`) once the four sites above were migrated, so it is not
  carried forward as unused surface here — it remains available upstream in
  `go-qrdb` for callers that still need it.

  **BREAKING for a Go consumer that sets `KeyConfig.Password` or
  `CAKeystoreSoftwareConfig.Password` (also reachable as `sdk/go`'s
  `KeyConfig.Password` / `TrustedCAKeystoreSoftwareConfig.Password`)
  directly as a string** — e.g. `KeyConfig{Password: "secret"}` no longer
  compiles. Construct a `types.SecretValue{Raw: "secret"}` (unresolved,
  matching what a YAML/JSON decode produces) or, for plaintext already in
  hand, `types.NewLiteralSecretValue([]byte("secret"))` instead. Config
  documents on disk and `XKMS_`-prefixed environment overrides for these
  two fields are unaffected.

  Files: `pkg/types/types.go`, `pkg/types/types_secret.go`,
  `pkg/ca/config.go`, `pkg/server/server.go`,
  `pkg/trust/clusterca/backends.go`, `pkg/config/load.go`. Tests:
  `pkg/types/types_secret_test.go`, `pkg/types/types_extended_test.go`,
  `pkg/ca/config_test.go`, `pkg/ca/secret_wiring_test.go`,
  `pkg/server/secret_wiring_test.go`,
  `pkg/trust/clusterca/backends_test.go`. Verified by
  `go test ./pkg/config/... ./pkg/server/... ./pkg/types/... ./pkg/ca/...
  ./pkg/trust/clusterca/...` and the full repository suite: a config file
  with a plain-string password still loads into a resolved-ready
  `SecretValue`, an environment override still applies, the CA-init wiring
  borrows bytes via `WithBytes` and the source config never carries a bare
  password string, and a `SecretValue` resolved to an empty credential
  leaves `attrs.Password` `nil` rather than treating its `credential://...`
  reference as a password.
