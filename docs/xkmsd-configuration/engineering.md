# xkmsd Configuration — Engineering Contract

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface — `pkg/config`

| Symbol | Contract |
|---|---|
| `Load(path string) (*Config, error)` | Resolves defaults → file → environment, then `Validate`. Returns `*errs.Wrapped` with message `failed to read config file`, `failed to parse config file` or `invalid configuration`. |
| `Defaults() *Config` | The defaults layer. The only place an infrastructure literal may live. |
| `DefaultServerHost` | `""` — every interface, dual-stack. See architecture.md for why not `0.0.0.0`. |
| `ServerConfig.Host` | The bind host shared by every network listener and handed to the embedded qrdb node. |
| `ServerConfig.TrustedProxies` (`yaml:"trusted_proxies"`, `pkg/config/config.go:366`) | Reverse proxies (IP or CIDR) whose `X-Forwarded-For` / `X-Real-IP` the REST rate limiters believe. Empty trusts none. `Validate` parses it with `ratelimit.ParseTrustedProxies` (`config.go:1489`) and fails with `*errs.Wrapped` around `*ratelimit.InvalidTrustedProxyError`; `pkg/server` parses it again into `rest.Config.TrustedProxies` (`pkg/server/server.go:2892`), and `cmd/xkmsd/acme.go`'s `startACMEServer` (`acme.go:164`) parses it a third time for the embedded ACME listener, feeding the identical result into `acmeserver.TrustedProxies` (the ACME rate limiter's resolver) and `audit.SetTrustedProxies` (`acme.go:168-169`, `pkg/acme/audit/hooks.go:117`) — one config key drives REST rate limiting, ACME rate limiting, and ACME audit source-IP attribution alike. Resolution rules: `pkg/ratelimit/clientip.go:102`. IPv6 rate-limit *bucket keys* (not audit records) are additionally folded to their `/64` by `ratelimit.RateLimitKey` (`clientip.go:171`); see `docs/acme-issuance/engineering.md`. |

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

## Exported surface — `pkg/server`

| Symbol | Contract |
|---|---|
| `New(cfg *config.Config, opts ...Option) (*Server, error)` (`pkg/server/server.go`) | Calls `cfg.Validate()` first, before any filesystem or storage touch. A failure is returned as `*ErrServiceInit{Service: "configuration"}` wrapping `Validate`'s typed error. `Validate` also normalizes `cfg` in place (defaults `Storage.Backend` to `"pebble"`, `Storage.QRDB.Transport` to `"embedded"`, `Cluster.ShardID` to `1`), so every subsystem `New` initializes afterward sees the normalized values. |
| `config.Config.LoopbackDesktop` (`pkg/config/config.go`, `yaml:"-"`) | Pure embedder signal, unreachable from any config file/env/flag. Set only by `pkg/server/loopback.desktopConfig`, which forces `Protocols.REST` on for the 127.0.0.1-only desktop engine listener. `Validate` reads it to skip, for that one launch shape, the `datastore.mode "standalone"` + `tls.enabled` requirement `NetworkServing` otherwise imposes on any REST-enabled config — no other check is affected. |

## Invariant — `Server.New` always validates

Before go-xkms#666, `config.Load` called `Validate`, but `server.New` did not
call it itself — a caller that built `*config.Config` by hand (an embedder,
or a test) could reach `New` with a configuration `Load` would have refused,
including an empty `storage.path` that a PIN-manager or TPM2-backend code
path then resolved directly against the filesystem (`Storage.Path + "/pin"`,
pre-#666), reaching the filesystem root when the path was empty. `New` now
calls `cfg.Validate()` unconditionally as its first action, so `config.Load`
callers and hand-built-`*config.Config` callers get the identical fail-closed
check; there is no path through `New` that skips it. `initializePINManager`
and `initializePasswordStore` (`pkg/server/server.go`) additionally guard
`storage.path` directly and use `filepath.Join`, for defense in depth if
either is ever reached without going through `New`.

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
9. **Network serving is the unified API server.** `NetworkServing` is true
   when any of `protocols.rest`, `grpc`, `quic` or `mcp` is on
   (`pkg/config/config.go:345`); the Unix socket never counts. Such a
   configuration must set `datastore.mode: standalone`, because the embedded
   qrdb node's multi-protocol server owns those ports, and `tls.enabled`,
   because its transports are TLS-only; `Validate` refuses either omission
   (`config.go:1551-1557`). `cert_file`/`key_file` stay optional: without them
   a bootstrap certificate serves until the CA issues the real one. QUIC is
   HTTP/3 on the REST port, advertised via `Alt-Svc` (`config.go:336-338`).

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
  behaviour: the file's plain `credential://...` reference lands unresolved
  in the field's `Raw`. Every secret-bearing config field is one:
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

  **The go-qrdb protected-target contract (go-xkms#654).** Every field in
  the list above is `*types.SecretValue` (a pointer), never the bare value
  type, and that is load-bearing, not stylistic: go-qrdb's
  `pkg/secret.ConfigProcessor` (the walker `resolveConfigSecrets` runs, see
  below) treats a `SecretValue` reached by *value* as **always required** —
  an empty one fails the walk outright — and the *only* way to spell an
  optional secret is a `nil *SecretValue`, which the walker's own
  `reflect.Pointer` case skips before it can ever become a failure. A
  non-nil protected target, in turn, **must reference a secret held
  elsewhere**: an empty value, a bare literal (`pin: "1234"`), an inline
  `literal://...` secret, and an unclaimed scheme are all refused with
  `*secret.UnresolvableTargetError`, whatever code path produced them —
  including a value built directly in Go (e.g. via
  `types.NewLiteralSecretValue`) and only later placed somewhere the walker
  reaches. There is no config-file, environment, or CLI-flag way to give one
  of these fields a literal secret any more; every one must be a
  `credential://<name>` reference resolved through the qrdb credential
  store. `types.SecretValueBytes` mirrors this: it is a thin borrow over an
  *already-resolved* enclave, and refuses (with
  `*types.SecretReferenceUnresolvedError`) a configured field whose enclave
  is still empty — including a bare literal — rather than falling back to
  `Raw`, which was go-xkms#654's original divergence from the contract
  above. The former `types.SecretValueSet` helper is deleted for the same
  reason it is dispensable: in the pointer-based field model, "is this
  configured" is answered by the field itself (`field != nil`), not a
  resolution-dependent wrapper.

  Resolution into the field's go-enclave sealed enclave happens later, wherever the
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
  - **Resolved today too, in the same one pass, now that backends init
    after unseal (go-xkms#653 approved item 2)**: `rng.pkcs11.pin`,
    `backends.pkcs11.pin`, `backends.awskms.secret_key`,
    `backends.azurekv.client_secret`, and `backends.vault.token`.
    `Server.New` runs `initializeQRDBStorage` (which, with a barrier,
    blocks until the qrdb node's own barrier is unsealed — see the
    seal/barrier section below) and `resolveConfigSecrets` *before*
    `initializeBackends`, so a `credential://` reference for any of these
    five fields resolves exactly like a CA password or the phone backend's
    Noise static key already did.
    `TestBackendCredentials_ResolveViaCredentialReference`
    (`pkg/server/secret_wiring_test.go`) proves all five end to end. There
    is no cycle: the node seal never reads an initialized backend.
    `embeddednode.ResolveNodeSeal` builds every hardware and cloud seal
    strategy from config before the node opens, and takes the PKCS#11 PIN
    and the Vault token from the pre-barrier store, not from these fields.

  - **Still genuinely unresolvable**: every `pkg/tpm2.Config`
    hierarchy-auth/password field. There is no config-file path from
    `pkg/config.Config` to `pkg/tpm2.Config` at all today (it is populated
    directly in Go — the `xkey tpm` CLI's `--hierarchy-auth` flag, tests),
    so `resolveConfigSecrets` never reaches them regardless of ordering.
    `types.SecretValueBytes`'s reference-shape guard still protects both:
    a `scheme://`-shaped value nothing resolved fails with
    `*types.SecretReferenceUnresolvedError` rather than being used verbatim.

    There is no equivalent caveat for the barrier's own boot secret: #653
    also removed `barrier.passphrase` (and the `--seal-passphrase` flag /
    `XKMS_BARRIER_PASSPHRASE` env var) entirely. The barrier never
    auto-unseals from configuration at all any more — see
    `docs/sealing-and-barrier/` and `docs/xkmsd-configuration/cli.md` for the
    replacement (a registered hardware seal strategy, or operator-driven
    unseal through go-qrdb's barrier surface).

## Authentication and client-certificate settings

`Server.buildAuthenticator` (`pkg/server/server.go:1257`) turns `auth.*` into
one authenticator and fails closed on anything it does not recognize:

| `auth.type` | Result | Refused with |
|---|---|---|
| `none`, `noop`, empty, or `auth.enabled: false` | no-op, every request anonymous; `Config.ComplianceGaps` flags it, so `xkmsd` will not start on it (`server.go:1276-1294`) | — |
| `jwt` | `JWTAuthenticator` (`:1296`) | `ErrJWTPublicKeyRequired` without `auth.jwt.public_key_file` (`pkg/server/errors.go:57`) |
| `mtls` | `MTLSAuthenticator` over the qrdb user store (`:1309`) | `ErrMTLSRequiresTLS` without `tls.enabled` (`errors.go:71`) |
| `composite` | see below (`:1322`) | |
| `adaptive` | removed: first boot provisions the administrator's credential, so there is no anonymous window to bridge (`:1329`) | `*ErrAdaptiveRemoved` (`errors.go:142`) |
| anything else | — | `*ErrUnknownAuthType` (`errors.go:493`) |

With `auth.composite.methods` set, each name goes through a `jwt`/`mtls`
factory map (`createCompositeAuthenticator`, `server.go:1371`): `jwt` without
a public key file fails `ErrCompositeJWTRequired`, `mtls` without TLS fails
`ErrCompositeMTLSRequiresTLS`, and any other name fails
`ErrUnknownCompositeMethod`, each wrapped in `*ErrCompositeMethodCreate`
(`errors.go:77-83`). With no methods listed the chain is derived
(`deriveCompositeAuthenticator`, `server.go:1423`): `jwt` when a key file or
the token issuer exists, `mtls` when TLS is on; a single member is used bare,
and none fails `ErrCompositeMethodsRequired` (`errors.go:74`). The chain
returns the first member's success, or the last member's error
(`pkg/auth/composite.go:50-60`).

`JWTAuthenticator` and `OIDCAuthenticator` pin `jwt.WithValidMethods` to the
verification key's own family — RS\*/PS\* for RSA, ES\* for ECDSA, EdDSA for
Ed25519 (`validMethodsForKey`, `pkg/auth/jwtalg.go:77`; `jwt.go:182`,
`oidc.go:447`) — so an `HS256` token keyed with the public key's bytes never
verifies. Any other key type, including a JWKS `oct` key, is
`*UnsupportedVerificationKeyError`. OIDC further intersects that set with the
provider's `id_token_signing_alg_values_supported` and refuses an empty
intersection as `*NoCommonSigningAlgorithmError` (`oidc.go:435`).

Both listeners map `tls.client_auth` the same way (`server.go:3442-3451`,
`parseClientAuthMode`, `pkg/server/unified_tls.go:128`):

| `tls.client_auth` | `crypto/tls` policy |
|---|---|
| `require`, `require_and_verify` | `RequireAndVerifyClientCert` |
| `verify` | `VerifyClientCertIfGiven` — what a composite `jwt` + `mtls` deployment needs, so bearer-only clients still connect |
| `request` | `RequestClientCert` |
| `none`, empty, anything else | `NoClientCert` |

After the embedded CA composes, the unified listener verifies client
certificates against the union of `tls.ca_file`, `tls.client_cas` and the
CA's own bundle, not the bundle alone (`unifiedClientCAPool`,
`unified_tls.go:198`, called at `:174`). `auth.piv_login.enabled` refuses an
empty or `none` `tls.client_auth` (`pkg/config/config.go:1632-1636`).
`tls.prefer_server_ciphers` and `tls.watch_cert_files` are parsed
(`config.go:413`, `:416`) but read by nothing: certificates are not reloaded
when the files change.

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
| `pkg/server` `TestNew_EmptyStoragePath_RejectedBeforeAnyFilesystemWrite` | `New` refuses an empty `storage.path` before any subsystem touches the filesystem; nothing is created under the working directory |
| `pkg/server` `TestNew_InvalidConfig_RejectedWithTypedError`, `TestNew_ValidConfig_Succeeds` | `New` wraps any `Validate` failure as `*ErrServiceInit{Service: "configuration"}`, and still constructs normally for a configuration `Validate` accepts |
| `pkg/server` `TestConfig_Validate_LoopbackDesktopExemptsNetworkServingRequirements`, `TestConfig_Validate_LoopbackDesktopDoesNotExemptOtherRESTConfigs` | `Config.LoopbackDesktop` skips the network-serving requirement for exactly the loopback desktop launch shape, and only that shape |
| `pkg/server/loopback` `TestDesktopConfig_ForcesLoopbackRESTOnly`, `TestLaunch_BindsLoopbackOnly` | `desktopConfig` sets `LoopbackDesktop`, and a real loopback launch still succeeds through `New`'s `Validate` call |

Run: `make test-config`, `make test-server`, `go test ./cmd/xkmsd/ ./pkg/api/grpc/`.
