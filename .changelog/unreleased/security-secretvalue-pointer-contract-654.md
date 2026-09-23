- **Every secret-bearing config field is `*types.SecretValue`, and a literal
  secret in one is now refused at start-up — BREAKING.** go-xkms#654
  originally declared these fields as the bare `types.SecretValue` value and
  had `Server.resolveConfigSecrets` swallow the resulting
  `*secret.UnresolvableTargetError` as tolerable, which diverged from
  go-qrdb's own protected-target contract
  (`go-qrdb/pkg/secret.ConfigProcessor`): a value-typed target is always
  required (an empty one fails the walk), the only way to spell an optional
  secret is a `nil *SecretValue`, and a protected target must reference a
  secret held elsewhere — an inline `literal://` secret or a bare value is
  refused, never honoured. This change brings xkms back into line: every
  field in `pkg/config` (`ca_key_passphrase`, `rng.pkcs11.pin`,
  `backends.pkcs11.pin`, `backends.awskms.secret_key`,
  `backends.azurekv.client_secret`, `backends.vault.token`,
  `backends.phone.noise_static_key`), `pkg/tpm2/config.go` (`lockout-auth`
  and every `ek`/`ssrk`/`idevid`/`iak`/`ldevid`/`lak` `hierarchy-auth`/
  `password`), `pkg/backend/tpm2`, `pkg/backend/azurekv`,
  `pkg/backend/pkcs11` (`pin`/`so-pin`), `pkg/ca/config.go`
  (`keys[*].password`, `keystores.*.password`/`pin`), and `pkg/types.KeyConfig.Password`
  (`ca.identity[*].keys[*].password`) is now `*types.SecretValue`; nil means
  unconfigured. `Server.resolveConfigSecrets` (`pkg/server/secret_wiring.go`)
  no longer filters `*secret.UnresolvableTargetError` out of the walk's
  result — every error `secret.ConfigProcessor` reports now fails
  `Server.New` with the typed, unmodified qrdb error joined into
  `*ErrConfigSecretResolution`. `types.SecretValueBytes` no longer falls
  back to an unresolved `Raw` as plaintext; it refuses a configured-but-
  unresolved value (including a bare literal) with
  `*types.SecretReferenceUnresolvedError` instead of trusting it. The
  presence-check helper `types.SecretValueSet` is deleted: with every field
  now a pointer, "is this configured" is answered by the field itself
  (`field != nil`), and every former caller (`pkg/backend/pkcs11`,
  `pkg/backend/azurekv`) now compares directly. `types.NewLiteralSecretValue`
  (and its `sdk/go` re-export) now returns `*types.SecretValue` to match —
  it remains the correct, qrdb-sanctioned way to build a `SecretValue` from
  a runtime value (a CLI flag, a Go-code default) that a
  `secret.ConfigProcessor` walk never reaches, such as `xkey`'s
  `--hierarchy-auth` flag or `pkg/tpm2.DefaultConfig`'s well-known EK auth —
  but it must never be assigned into a field the walker does reach, since a
  literal there is refused regardless of how it was constructed.
  The PKCS#11, RNG-PKCS#11, AWS KMS, Azure Key Vault and Vault backend
  credentials are unaffected in practice: go-xkms#653's companion change
  (see that entry) moves `Server.resolveConfigSecrets` before
  `initializeBackends`, so a `credential://` reference for all five now
  resolves in the same pass as everything else; only a bare literal for
  them is refused, exactly like every other protected field. Files:
  `pkg/config/config.go`, `pkg/tpm2/config.go`,
  `pkg/tpm2/key.go`, `pkg/tpm2/provision.go`, `pkg/backend/tpm2/config.go`,
  `pkg/backend/azurekv/config.go`, `pkg/backend/azurekv/azurekv.go`,
  `pkg/backend/pkcs11/config.go`, `pkg/backend/pkcs11/pkcs11.go`,
  `pkg/backend/pkcs11/pkcs11_ecdh.go`,
  `pkg/backend/pkcs11/pkcs11_importexport.go`, `pkg/ca/config.go`,
  `pkg/types/types.go`, `pkg/types/types_secret.go`,
  `pkg/server/secret_wiring.go`, `pkg/server/backend_awskms.go`,
  `pkg/server/backend_vault.go`, `pkg/server/backend_phone.go`,
  `pkg/server/cluster_ca_strategy.go`, `xkey/pkg/gui/app.go`,
  `docs/xkmsd-configuration/engineering.md`.
