# xkmsd Configuration — Engineering Contract

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-09-21

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
| `legacyEnv(legacyName, key)` | Reads a legacy name only when non-empty and only when the key's canonical name is absent (`os.LookupEnv`). Legacy names are never bound in viper: `AllowEmptyEnv` would turn `XKMS_HOST=` into a bind-all request. |
| `canonicalEnvName(key)` | `server.host` → `XKMS_SERVER_HOST`. |
| `applyEnvOverrides(cfg)` | The legacy ladder (`XKMS_HOST`, `XKMS_REST_PORT`, …), every read through `legacyEnv`. Runs after unmarshal; same layer as viper's environment. Shrinks as clusters are remediated. |
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
   over the file and over `XKMS_HOST` (`AllowEmptyEnv`; the legacy ladder
   tests presence with `os.LookupEnv`).
5. **The canonical environment name wins over its alias**, and over every
   legacy name the ladder still owns: `applyEnvOverrides` reads a legacy name
   through `legacyEnv`, which yields nothing while the key's canonical
   `XKMS_<SECTION>_<KEY>` is set, so viper's resolution of the canonical name
   stands. A legacy name that already is the canonical spelling is read as is.
6. **A value that cannot decode into its field's type fails `Load`**; it is not
   silently dropped. (The legacy ladder still drops an unparsable port for the
   names it owns; that behaviour leaves with the ladder.)
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

## Decoding notes

viper reads the YAML into a map before mapstructure decodes it with
`TagName = "yaml"`. Two consequences differ from a direct `yaml.Unmarshal`:

- map keys are lowercased (the only map-typed field, `attestation.formats`, is
  matched case-insensitively by its consumer, so nothing changes);
- an unquoted scalar such as `socket_mode: 0660` is a YAML integer, so a
  string field receives `"432"`. The shipped configurations quote such values;
  operators must too;
- a `types.SecretValue` field (`ca.identity[*].keys[*].password`,
  `ca.identity[*].keystores.software.password`) does not decode through
  `SecretValue.UnmarshalYAML` — mapstructure has no notion of `yaml.Unmarshaler`
  — so `Load` composes `stringToSecretValueHookFunc` onto the decoder to give
  it the same behaviour: the file's plain string (a literal password or a
  `credential://...` reference) lands unresolved in the field's `Raw`.
  Resolution into the field's memguard enclave happens later, wherever the
  field's owner has a `secret.ResolverRegistry` available (`pkg/server`'s
  `initializeCA` for these two fields) — `Load` itself never resolves a
  secret reference.

## Errors

`Load` wraps with `errs.Wrapped`. `pkg/api/grpc.Start` wraps the listen error
with `errs.Wrapped{Msg: "failed to listen on <addr>"}`.

## Tests

| Test | Proves |
|---|---|
| `pkg/config` `TestLoad_ServerHost_*` | each layer settable; env over file; env without file key; alias; canonical over alias |
| `pkg/config` `TestLoad_CanonicalEnvResolvesEveryKey` | the binding is generic (`XKMS_SERVER_GRPC_PORT`) |
| `pkg/config` `TestLoad_EnvValueOfWrongTypeIsRejected`, `TestLoad_MalformedFileIsRejected` | error handling |
| `cmd/xkmsd` `TestServerHost_Precedence` | flags > env > file > defaults end to end |
| `cmd/xkmsd` `TestServerHost_UnsetFlagDoesNotClobber` | `Changed()` semantics, including `--host ""` |
| `pkg/server` `TestBuildRESTConfig_CarriesConfiguredHost` | `server.host` reaches `rest.Config.Host` |
| `pkg/api/grpc` `TestServer_StartBindsConfiguredHost` | the gRPC listener binds the configured host |
| `pkg/api/grpc` `TestServer_StartRejectsUnbindableHost` | typed error, no wildcard fallback |

Run: `make test-config`, `make test-server`, `go test ./cmd/xkmsd/ ./pkg/api/grpc/`.
