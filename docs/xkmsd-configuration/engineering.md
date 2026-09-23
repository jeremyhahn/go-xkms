# xkmsd Configuration — Engineering Contract

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-09-23

## Exported surface — `pkg/config`

| Symbol | Contract |
|---|---|
| `Load(path string) (*Config, error)` | Resolves defaults → file → environment, then `Validate`. Returns `*errs.Wrapped` with message `failed to read config file`, `failed to parse config file` or `invalid configuration`. |
| `Defaults() *Config` | The defaults layer. The only place an infrastructure literal may live. |
| `DefaultServerHost` | `""` — every interface, dual-stack. See architecture.md for why not `0.0.0.0`. |
| `ServerConfig.Host` | The bind host shared by every network listener and handed to the embedded qrdb node. |

Unexported but load-bearing, all in `pkg/config/load.go`:

| Symbol | Contract |
|---|---|
| `envPrefix` | `XKMS`. The product name, not the binary name. |
| `newConfigViper()` | Registers `Defaults()` as known keys, then `SetEnvPrefix` + `SetEnvKeyReplacer` (`.` and `-` → `_`) + `AllowEmptyEnv` + `AutomaticEnv`, then `registerEnvKeys` binds every leaf key of the tree by name. |
| `registerEnvKeys(v)` / `walkYAMLKeys` | Walk `Config` by yaml tag, pointer sections through their element type, and `BindEnv` each leaf key. No value is registered, so a section stays nil until something sets a key in it. |
| `canonicalEnvName(key)` | `server.host` → `XKMS_SERVER_HOST`. The only environment name any key resolves under; there is no alias or legacy-name ladder. |
| `stringToSecretValueHookFunc` | mapstructure decode hook, composed onto viper's default hook in `Load`. Decodes a scalar string into a `types.SecretValue` field's `Raw` (unresolved), giving mapstructure the same behaviour `SecretValue.UnmarshalYAML` provides for a direct `yaml.Unmarshal`. |
| `secretValueType` | `reflect.TypeOf(types.SecretValue{})`. Used by both the decode hook and `walkYAMLKeys` to give `SecretValue` leaf-value treatment instead of struct-section treatment. |

## Exported surface — `cmd/xkmsd`

| Symbol | Contract |
|---|---|
| `registerServerFlags(fs) *serverFlags` | Declares `--host` on `fs`. |
| `(*serverFlags).apply(cfg, fs)` | Writes each flag that was set into `cfg`. Never writes a flag's default. |
| `flagWasSet(fs, name) bool` | `flag.Visit`-based `Changed()` for the standard library flag set. |

## Exported surface — `pkg/api/grpc`

| Symbol | Contract |
|---|---|
| `ServerConfig.Host` | Bind host of the listener; empty binds every interface. |
| `(*Server).Start()` | Binds `net.JoinHostPort(Host, Port)`. Port `0` is ephemeral; `Port()` reports the bound port. A host that cannot be bound returns `*errs.Wrapped` and leaves `Port()` at 0. |

## Invariants

1. **No listener holds an address literal.** Every `net.Listen` / `http.Server.Addr`
   on the daemon path consumes `config.Server.Host`; `pkg/api/grpc` consumes
   `ServerConfig.Host`. Address strings are built by `Server.listenAddr`
   (`net.JoinHostPort`), so an IPv6 host is bracketed for every listener.
   The enroll-01 credential-activation listener a joining node serves during
   ACME enrollment is a daemon listener too: `server.host` reaches it as
   `clusterca.ACMEOptions.ChallengeHost` → `acmeclient.EnrollmentConfig.ListenHost`
   (#140 cluster 2).
2. **Precedence is flags > env > file > defaults**, and a flag participates only
   when set. A SIGHUP resolves the new configuration through the same layers
   (`resolveReloadConfig` in `cmd/xkmsd`), so a flag set at start-up survives
   every reload.
3. **Every key of the configuration tree resolves from the environment**,
   whether or not the file mentions it: `registerEnvKeys` binds each leaf key
   to its canonical name, walking pointer sections (`webauthn`, `ca`, `acme`,
   `attestation`, `trust`, `backends.*`) through their element type. A bound
   key carries no value, so a pointer section stays nil unless the file or
   the environment sets a key in it. Hyphens in a key (`trust.server-url`)
   become underscores in the name (`XKMS_TRUST_SERVER_URL`). A `types.SecretValue`
   field is walked as a leaf, never descended into as a section — its wire
   shape is a single scalar reference string, and descending into its
   unexported enclave field would register zero leaf keys, silently dropping
   it from environment resolution.
4. **A present environment variable is a value, empty included.**
   `XKMS_SERVER_HOST=""` clears a pinned host to bind every interface and wins
   over the file (`AllowEmptyEnv`).
5. **`XKMS_<SECTION>_<KEY>` is the only environment name any key resolves
   under.** There is no legacy or pre-viper alias ladder (removed go-xkms#140
   / go-xkms#35): a variable spelled any other way is not read, and an
   operator's unit file carrying an old name silently stops taking effect
   rather than winning or losing a precedence contest.
6. **A value that cannot decode into its field's type fails `Load`**; it is not
   silently dropped.
7. **Every SAN on the auto-issued server certificate is configuration.** The
   bootstrap and the CA-issued certificate share one builder,
   `Server.serverCertSANs`: `tls.server_cn`, `tls.extra_sans`, `server.host`,
   the cluster peers, and the loopback names only while
   `tls.include_localhost_sans` (defaults-layer `true`) says so. No SAN is a
   literal, and a wildcard address is never one (#140 cluster 3). The machine
   hostname is node-local and goes into the bootstrap certificate only: the
   CA-issued certificate is shared by every node through replicated storage,
   so its SAN set is deterministic cluster-wide, and a certificate whose set
   no longer matches is retired and reissued rather than served stale.
8. **A field this package removes is gone outright, not deprecated in
   place.** There is no reader that still parses a retired key so an old
   config file "still works" — an old key is simply unknown, and this
   package's config loaders ignore unknown YAML/JSON keys (go-xkms#35 removed
   `config.NoiseBootstrapConfig`'s four `static_key_*` / `p256_static_key_*`
   fields this way: the bootstrap static keys are barrier-sealed, persisted-
   file, or generated — see
   [`../trust-bootstrap/engineering.md`](../trust-bootstrap/engineering.md)
   §Configuration for that custody decision, which this file does not own).

## Decoding notes

viper reads the YAML into a map before mapstructure decodes it with
`TagName = "yaml"`. Two consequences differ from a direct `yaml.Unmarshal`:

- map keys are lowercased (the only map-typed field, `attestation.formats`, is
  matched case-insensitively by its consumer, so nothing changes);
- an unquoted scalar such as `socket_mode: 0660` is a YAML integer, so a
  string field receives `"432"`. The shipped configurations quote such values;
  operators must too;
- a `types.SecretValue` field does not decode through `SecretValue.UnmarshalYAML`
  — mapstructure has no notion of `yaml.Unmarshaler` — so `Load` composes
  `stringToSecretValueHookFunc` onto the decoder to give it the same
  behaviour: the file's plain string (a literal password or a
  `credential://...` reference) lands unresolved in the field's `Raw`. Every
  secret-bearing config field is one: `barrier.passphrase`,
  `rng.pkcs11.pin`, `backends.pkcs11.pin`, `backends.awskms.secret_key`,
  `backends.azurekv.client_secret`, `backends.vault.token`,
  `backends.phone.noise_static_key`, `ca.identity[*].keys[*].password`,
  `ca.identity[*].keystores.software.password`,
  `ca.identity[*].keystores.pkcs11.pin`,
  `cluster.raft_enrollment.ca_key_passphrase`, every `tpm2.*` hierarchy
  auth/password field (`pkg/tpm2.Config`'s `lockout-auth`, each of
  `ek`/`ssrk`/`idevid`/`iak`/`ldevid`/`lak`'s `hierarchy-auth`/`password`),
  and the `pkg/backend/azurekv` and `pkg/backend/pkcs11` package-local
  `Config.client_secret`/`pin`/`so-pin`. `backends.pkcs11.token` (a token
  label, not a credential) and `bootstrap.raft.*.spki_pin` (a public SHA-256
  hash) stay plain strings — see `pkg/secure/analyzer`'s field-name allowlist
  for why those two are never flagged despite the naming.

  Resolution into the field's memguard enclave happens later, wherever the
  field's owner has a `secret.ResolverRegistry` available — `Load` itself
  never resolves a secret reference. Two groups, by when in the daemon's
  life that owner exists:

  - **Resolved today, in one pass, at server start**: `Server.resolveConfigSecrets`
    (`pkg/server/secret_wiring.go`) runs go-qrdb's canonical
    `secret.ConfigProcessor` once over the entire loaded `*config.Config`,
    right after `initializeCredentialService` — the earliest point
    `Server.buildSecretRegistry` actually has a `credential://` resolver
    registered — and before every consumer that reads a resolved field:
    `initializeCA` for `ca.identity[*].keys[*].password`,
    `ca.identity[*].keystores.software.password` and
    `ca.identity[*].keystores.pkcs11.pin`; `resolveClusterCAKeyPassphrase`
    (called from `initializeCA`'s post-node path) for
    `cluster.raft_enrollment.ca_key_passphrase`; and `RegisterPhoneBackend`
    for `backends.phone.noise_static_key` (always called well after boot, so
    always after this pass has already run). Every one of those call sites
    now reads its field through `types.SecretValueBytes` /
    `types.NewPasswordFromSecretValue` alone — none of them resolves a
    reference itself any more. The walker's protected-`SecretValue` target
    is strict — it must reference a secret a registered resolver actually
    claims, or it is reported — so an unconfigured field (empty `Raw`) or an
    operator-supplied literal is reported internally too
    (`secret.UnresolvableTargetError`); `resolveConfigSecrets` treats that as
    the expected non-fatal case (`types.SecretValueBytes` already handles an
    empty or literal `SecretValue` correctly without ever going through this
    processor) and only fails `Server.New`, with the typed
    `*server.ErrConfigSecretResolution`, when the registry DID claim a
    reference and genuinely failed to fetch it.
  - **Still cannot be resolved through the credential store, structurally**:
    `barrier.passphrase`, `rng.pkcs11.pin`, `backends.pkcs11.pin`,
    `backends.awskms.secret_key`, `backends.azurekv.client_secret`,
    `backends.vault.token`, and every `tpm2.*` hierarchy auth/password field.
    `resolveNodeSeal` (which needs `barrier.passphrase`) and
    `initializeBackends` (which needs the rest) both run *before*
    `initializeCredentialService` in `Server.New` — and credential service
    construction itself needs `s.barrier`, which for a hardware seal strategy
    needs `initializeBackends` to have already run — so `resolveConfigSecrets`
    cannot run early enough to help them either: it needs the same credential
    service they are consumed ahead of. Resolving a `credential://` reference
    for any of these fields through the internal credential store would mean
    asking the barrier to unseal itself, or a backend to authenticate, using a
    secret held in the store that same barrier/backend protects.
    `types.SecretValueBytes` (the shared borrow helper every one of them
    uses to reach the plaintext) refuses a value shaped like an unresolved
    reference — `Strategy` still the zero value and `Raw` matching
    `scheme://name` — with `*types.SecretReferenceUnresolvedError`, failing
    `Server.New` outright rather than silently using the reference text as
    the secret. A literal value (or one an env var/flag supplies) works
    exactly as before; a `credential://...` value for one of these fields
    fails loudly at start-up today, and is expected to keep doing so until a
    boot-time resolver that does not depend on the barrier (an env-only or
    external-KMS resolver, deliberately distinct from the
    credential-store-backed one) is scoped and reviewed as its own change.
    The `pkg/tpm2.Config` hierarchy-auth/password fields are additionally
    never reached by `resolveConfigSecrets` at all: there is no config-file
    path from `pkg/config.Config` to `pkg/tpm2.Config` today (it is populated
    directly in Go — the `xkey tpm` CLI's `--hierarchy-auth` flag, tests).
    `SecretValueBytes`'s same reference-shape guard still protects it if a
    caller passes a `scheme://`-shaped literal by mistake.

## Errors

`Load` wraps with `errs.Wrapped`. `pkg/api/grpc.Start` wraps the listen error
with `errs.Wrapped{Msg: "failed to listen on <addr>"}`.

## Tests

| Test | Proves |
|---|---|
| `pkg/config` `TestLoad_ServerHost_*` | each layer settable; env over file; env without file key |
| `pkg/config` `TestLoad_CanonicalEnvResolvesEveryKey` | the binding is generic (`XKMS_SERVER_GRPC_PORT`) |
| `pkg/config` `TestLoad_EnvValueOfWrongTypeIsRejected`, `TestLoad_MalformedFileIsRejected` | error handling |
| `cmd/xkmsd` `TestServerHost_Precedence` | flags > env > file > defaults end to end |
| `cmd/xkmsd` `TestServerHost_UnsetFlagDoesNotClobber` | `Changed()` semantics, including `--host ""` |
| `pkg/server` `TestBuildRESTConfig_CarriesConfiguredHost` | `server.host` reaches `rest.Config.Host` |
| `pkg/api/grpc` `TestServer_StartBindsConfiguredHost` | the gRPC listener binds the configured host |
| `pkg/api/grpc` `TestServer_StartRejectsUnbindableHost` | typed error, no wildcard fallback |
| `pkg/server` `TestResolveConfigSecrets_LiteralAndEmptyFieldsAreNoOps` | an operator-supplied literal and an unconfigured field both survive the whole-config walk unchanged |
| `pkg/server` `TestResolveConfigSecrets_ResolvesReferenceAcrossConfig` | a `credential://` reference anywhere in the config resolves in the same pass, alongside untouched literal/empty fields elsewhere |
| `pkg/server` `TestResolveConfigSecrets_UnresolvableReferenceFailsClosed`, `TestResolveConfigSecrets_UnresolvableCredentialReference` | a reference the registry claims but cannot fetch fails with the typed `*ErrConfigSecretResolution` |
| `pkg/server` `TestResolveClusterCAKeyPassphrase_*`, `TestRegisterPhoneBackend_ResolvableCredentialReference` | the CA/cluster/phone call sites read an already-resolved field through `types.SecretValueBytes` alone, no per-field `Resolve` of their own |

Run: `make test-config`, `make test-server`, `go test ./cmd/xkmsd/ ./pkg/api/grpc/`.
