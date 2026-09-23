- **BREAKING: every remaining secret-bearing config field typed as a plain
  `string` is now `types.SecretValue`, closing the last open part of the
  2026-08-17 audit (#3 part 3).** `pkg/config.Config`'s `barrier.passphrase`,
  `rng.pkcs11.pin`, `backends.pkcs11.pin` (the token PIN; `backends.pkcs11.token`
  — a slot label, not a credential — stays a string), `backends.awskms.secret_key`,
  `backends.azurekv.client_secret`, `backends.vault.token`, and
  `backends.phone.noise_static_key`; every hierarchy-auth/password field of
  `pkg/tpm2.Config` (`lockout-auth`, and each of `ek`/`ssrk`/`idevid`/`iak`/
  `ldevid`/`lak`'s `hierarchy-auth`/`password`); `pkg/backend/azurekv.Config.ClientSecret`
  and `pkg/backend/pkcs11.Config.PIN`/`SOPIN`; and `pkg/ca.CAKeystorePKCS11Config.Pin`
  now follow the `types.SecretValue` custody pattern #41 established for
  `KeyConfig.Password` and `CAKeystoreSoftwareConfig.Password`: the resolved
  plaintext is sealed into the field's own memguard enclave rather than kept
  as an unwipeable Go string, and every call site borrows it with
  `types.SecretValueBytes` (WithBytes-first, falling back to `Raw` for a
  value that was never resolved — the same priority `NewPasswordFromSecretValue`
  already used) or, where a third-party SDK requires a plain string or
  `[]byte` (miekg/pkcs11's `Login`, the Azure/AWS/Vault client constructors),
  at that one documented boundary. `SPKIConfig.Pin` (`bootstrap.raft.*.spki_pin`)
  is unchanged: it is a public SHA-256 hash, not a secret. `pkg/backend/tpm2.Config`
  gains a new `HierarchyAuth` field (additive) so the TPM2 backend can
  express an Owner-hierarchy auth for the Storage Root Key it provisions —
  previously that config had no way to express one at all. The YAML/JSON
  wire shape is unchanged for every field: each still decodes from, and
  re-encodes to, the same plain reference string. Go callers that construct
  these structs directly (embedders, tests, the SDK) must update to
  `types.SecretValue{Raw: "..."}` (an unresolved literal, matching a
  straight YAML/JSON decode) or `types.NewLiteralSecretValue([]byte("..."))`
  (a resolved literal, e.g. a CLI-flag value) in place of a bare string.
  `types.SecretValueBytes` now refuses, with the new typed
  `*types.SecretReferenceUnresolvedError`, any value shaped like a secret
  reference (`scheme://name`) that nothing has actually resolved — closing a
  real gap the first pass of this change left open: a `credential://...`
  value for one of these fields previously fell through to being used
  verbatim as the secret (the reference text itself), which is worse than
  the plain string it replaced. `backends.phone.noise_static_key` (resolved
  when a phone connects, well after boot) now resolves a `credential://`
  reference for real, through the same `Server.buildSecretRegistry` the CA
  identity passwords and the cluster CA passphrase already used — no second
  resolver. `barrier.passphrase`, `rng.pkcs11.pin`, `backends.pkcs11.pin`,
  `backends.awskms.secret_key`, `backends.azurekv.client_secret`,
  `backends.vault.token`, and the `tpm2.*` hierarchy-auth/password fields are
  consumed earlier in `Server.New` than the credential service exists to
  resolve anything (`resolveNodeSeal`/`initializeBackends` run before
  `initializeCredentialService`, which itself needs the barrier those fields
  help unseal), so a `credential://` reference for any of them fails
  `Server.New` outright with `*types.SecretReferenceUnresolvedError` instead
  of silently misusing the reference text; a literal value, or one an env
  var/flag supplies, is unaffected. See
  `docs/xkmsd-configuration/engineering.md`'s Decoding notes for the full
  per-field breakdown and the follow-up this leaves open (a boot-time
  resolver that does not depend on the barrier, scoped separately).
- **`Server.resolveConfigSecrets` (`pkg/server/secret_wiring.go`) replaces
  every ad-hoc `buildSecretRegistry().Resolve` call with go-qrdb's canonical
  `secret.ConfigProcessor`, run once over the whole loaded configuration
  right after `initializeCredentialService` — the earliest point in
  `Server.New` a `credential://` reference can actually be claimed — and
  before `initializeCA`, so every consumer it precedes
  (`ca.identity[*].keys[*].password`, `ca.identity[*].keystores.software.password`,
  `cluster.raft_enrollment.ca_key_passphrase`,
  `backends.phone.noise_static_key`) now reads an already-resolved field
  through `types.SecretValueBytes` alone; the per-field resolve loop this
  replaced in `Server.initializeCA`, `resolveClusterCAKeyPassphrase`, and
  `RegisterPhoneBackend` is deleted. A literal value and an unconfigured
  field are both left exactly as decoded — the processor's own
  `secret.UnresolvableTargetError` for either is the expected, tolerated
  outcome, not a failure — and `Server.New` fails only with the new typed
  `*server.ErrConfigSecretResolution` when the registry claimed a reference
  and genuinely could not fetch it (credential store error, missing
  credential). `resolveClusterCAKeyPassphrase`'s pre-node cluster-ACME
  bootstrap caller (`provisionRaftClusterACME`, which still runs before the
  credential service exists) picks up a real fix as a side effect: it used
  to call `buildSecretRegistry().Resolve` directly, so a `credential://`
  reference on that path silently fell through the registry's literal
  fallback and used the unclaimed reference text itself as the cluster CA
  key passphrase; it now goes through `types.SecretValueBytes` like every
  other caller and fails closed with `*types.SecretReferenceUnresolvedError`
  instead. The fields consumed earlier than `initializeCredentialService`
  (`barrier.passphrase`, `rng.pkcs11.pin`, `backends.pkcs11.pin`,
  `backends.awskms.secret_key`, `backends.azurekv.client_secret`,
  `backends.vault.token`, and the `tpm2.*` hierarchy-auth/password fields
  where a config path to them exists at all) are unaffected — the same
  structural chicken-and-egg gap `docs/xkmsd-configuration/engineering.md`
  already documented remains open, scoped separately.
