# SSH Keys, Known Hosts & Authorized Keys — Engineering Contract

> **Status: NORMATIVE** · Feature: `ssh-keys` · Repo: `go-xkms` · Last verified: 2026-09-28

No build tag gates any symbol in this document — see
[`architecture.md`](architecture.md).

## Exported surface — `pkg/ssh/keys`

| Symbol | Contract |
|---|---|
| `Algorithm` (`key.go:29`) | `AlgorithmEd25519`, `AlgorithmRSA`, `AlgorithmECDSAP256`, `AlgorithmECDSAP384`, `AlgorithmECDSAP521`. String values are the canonical on-disk identifiers — "MUST NOT change without a storage migration." |
| `GenerateOptions{Algorithm, RSABits, Comment}` / `Generate(opts) (*Key, error)` | `generate.go:37,63`. `RSABits` defaults to 4096 when zero; minimum enforced is 2048 (`minRSABits`) — a smaller request is `*InvalidKeySizeError`. Dispatches with an explicit `switch`, deliberately not a `map[Algorithm]func` — "each generator has a slightly different parameter signature; a map would force either an interface box... or a wrapper struct" (`generate.go:81`). |
| `Key` (`key.go:76`) | `IsBackendBacked() bool`, `ID() string`, `Destroy()`. `Material` is nil for a backend-backed key. |
| `(*Key).Signer() (ssh.Signer, error)` / `SignerWithClose()` | `signer.go:40,73`. Software-key signer. |
| `(*Key).BackendSigner(ctx, BackendProvider) (ssh.Signer, error)` | `signer.go:120`. Backend-backed signer — see `pkg/ssh/backend`. |
| `Store` interface: `Put`/`Get`/`Delete`/`List` (`store.go:39`) | `Get`/`Delete` on a missing key return `*KeyNotFoundError`. `List` returns records with `Material == nil` — the envelope is not opened during a list. |
| `BackendStore` (`store.go:94`) | The `storage.Backend`-backed `Store` implementation. `NewBackendStore(backend storage.Backend) (*BackendStore, error)`. Storage prefix `"ssh/keys/"` (`store.go:31`) — "changing this string is a disk-layout break that requires a migration." Envelope version `v2`; v1 (software-only, pre-backend-key) envelopes still load. |
| `Fingerprint(pub ssh.PublicKey) string` | `fingerprint.go:26`. OpenSSH `SHA256:<base64-no-padding>` form. |
| `ParsePEM(ctx, pemBuf *secure.Buffer, provider secure.PassphraseProvider) (*Key, error)` | `parse.go:51`. An encrypted PEM with no matching provider is `*PassphraseRequiredError`. |
| Typed errors (`errors.go`) | `NilInputError`, `UnsupportedAlgorithmError`, `InvalidKeySizeError`, `PassphraseRequiredError`, `PEMParseError`, `KeyMaterialError`, `KeyNotFoundError`, `StorageError`, `SerializationError`, `ClosedSignerError`, `BackendKeyIDTooLongError`. |

### `backendKeyID` — the backend CN encoding (go-xkms#1238)

`backendKeyID(sc scope.Scope, owner, name string) (string, error)`
(`generate.go:270`) derives `GenerateOnBackend`'s `types.KeyAttributes.CN`
from an SSH key's `(scope, owner, name)` identity. It is unexported —
`GenerateOnBackend` (`generate.go:186`) is the only caller — but the
encoding is a correctness invariant every backend-backed SSH key depends on,
so it is documented here rather than left to the source comment alone.

- **Injective.** `owner` and `name` are hex-encoded independently
  (`encoding/hex`) and joined as `"ssh-" + scope + "-" + hex(owner) + "-" +
  hex(name)` (`generate.go:270-283`). `hex.EncodeToString` only ever emits
  `[0-9a-f]`, so a `-` in the result can only be one of the three literal
  separators `backendKeyID` writes — it can never occur inside a hex segment
  — making the join unambiguous for any bytes `owner` or `name` contain. The
  prior encoding (`"ssh-" + strings.ReplaceAll("<scope>/<owner>/<name>",
  "/", "-")`) was not: `owner="a-b", name="c"` and `owner="a",
  name="b-c"` both flattened to `"ssh-user-a-b-c"`, so one caller's key
  could silently address, and overwrite, another's backend CN. See
  `pkg/ssh/keys/backend_keyid_test.go` (`TestBackendKeyID_InjectiveAcrossHyphenBoundary`,
  `TestBackendKeyID_PropertyNoCollisions`, `FuzzBackendKeyID_Injective`) and
  the end-to-end regression `pkg/ssh/tenancy/client_test.go`
  (`TestBackendKeys_DistinctAddressesDoNotCollide`).
- **Validated before encoding.** `scope.BuildKeyID(sc, owner, name)`
  (`generate.go:271`, `pkg/ssh/scope/scope.go:79`) is called first purely
  for its checks — non-empty `owner`/`name`, a valid `scope`, no embedded
  `/` — so callers keep seeing the same `*scope.ScopeInvalidError` /
  `*scope.KeyIDMalformedError` the old implementation returned; its
  `"<scope>/<owner>/<name>"` result is discarded, not reused for the CN.
- **Character set.** The result contains only `[a-z0-9-]` (the fixed `"ssh-"`
  prefix, the fixed scope word, and lowercase hex). That is colon-free,
  which the unified xkms key ID format requires — `types.KeyAttributes.ID()`
  (`pkg/types/types.go:1351`) and `pkg/keyprovider/pkcs8`'s
  `parseStorageKeyID` (`pkg/keyprovider/pkcs8/pkcs8.go:422`) split on `:`,
  so a `:` inside a CN shifts every field after it — and `/`-free, which the
  software and tpm2 backends require because they use the CN directly as a
  storage key (`pkg/storage.KeyPath`, `pkg/storage/namespace.go:24`;
  `pkg/tpm2/store.storageKey`, `pkg/tpm2/store/file_backend.go:48`), where an
  embedded `/` would nest a path instead of naming one key.
- **Bounded length.** `maxBackendKeyIDLen = 255` (`generate.go:240`) matches
  `pkg/validation.ValidateKeyID`'s own limit on every other xkms key
  identifier (`pkg/validation/validation.go:130`) and stays inside
  `NAME_MAX` on the filesystems the software/tpm2 file-per-key storage is
  deployed on. An identity whose encoded CN would exceed it is refused with
  `*BackendKeyIDTooLongError{Length, Max}` (`errors.go:22`) rather than
  truncated — truncation could itself collide two identities the same way
  the bug being fixed did.

## Exported surface — `pkg/ssh/backend`

| Symbol | Contract |
|---|---|
| `Resolver` / `ResolverFunc` (`provider.go:36,44`) | `ResolveKeyProvider(ctx, backendID string) (types.KeyProvider, error)` — the daemon wires this to `s.xkmsService.LookupBackend`. |
| `Provider` (`provider.go:51`) | `New(resolver Resolver) (*Provider, error)`. `GenerateKey(ctx, backendID, keyID string, algo keys.Algorithm, rsaBits int) (crypto.Signer, error)`, `Signer(ctx, backendID, keyID string, algo keys.Algorithm) (crypto.Signer, error)`, `DeleteKey(ctx, backendID, keyID string, algo keys.Algorithm) error`. |
| `SupportedAlgorithms(storeType types.StoreType) []keys.Algorithm` | `algorithms.go:61`. TPM 2.0 → RSA + ECDSA P-256/384/521 only (no Ed25519 key object type in TPM 2.0 — cites `pkg/backend/tpm2/backend.go`'s `GenerateKey` switch and `pkg/tpm2/ecdsa.go`'s `CreateECDSA`). Every other recognized store type, and any unrecognized one, gets the full 5-algorithm set — this function does not special-case cloud backends; each backend's own `GenerateKey` is authoritative for what it actually accepts. Returns a defensive copy. |
| Typed errors (`errors.go`) | `NilInputError`, `BackendNotFoundError`, `UnsupportedAlgorithmError`, `GenerateError`, `SignerError`, `DeleteError`. |

## Exported surface — `pkg/ssh/known_hosts`

| Symbol | Contract |
|---|---|
| `Pin` (`pin.go:54`) | `Host`, `Fingerprint` (`SHA256:...`), `Algorithm`, `Scope`, `Owner`, `AddedAt`, `Source`, `PublicKey []byte` (SSH wire format; required — `Add` rejects a nil `PublicKey` with `*PublicKeyRequiredError`). `Source` constants: `SourceManual`, `SourceFirstContact`, `SourceImport` (prefix, full value typically `"imported:<origin>"`). |
| `Store` interface: `Add`/`Get`/`List`/`Remove` (`store.go:40`) | |
| `BackendStore` (`store.go:86`) | `NewBackendStore(backend storage.Backend) (*BackendStore, error)`. A pre-v2 (fingerprint-only) pin decodes as `*LegacyPinError`, not a zero-`PublicKey` `Pin` — `Get`/`Verify` fail closed naming the host that must be re-pinned; `List` skips it. |
| `Verify` | Compares the full public key, not the fingerprint field alone. |
| `Callback` | Builds an `ssh.HostKeyCallback` from `Verify`. |
| Typed errors (`errors.go`) | `NilInputError`, `NoPublicKeyError`, `LegacyPinError`, `NotFoundError`, `DuplicateError`, `MismatchError`, `RejectedError`, `InvalidHostError`, `PublicKeyRequiredError`, `InvalidFingerprintError`, `StorageError`, `SerializationError`. |

## Exported surface — `pkg/ssh/authorized`

| Symbol | Contract |
|---|---|
| `Entry{Key *keys.Key, Options []string, Comment string}` | `entry.go:34`. Models exactly one `authorized_keys` line. `Options` are preserved verbatim; this package does not validate option semantics. |
| `Record{Scope, Owner, Name, AddedAt, Entry *Entry}` | `record.go:38`. Store metadata + parsed `Entry`; `Entry` is never nil on a `Record` this package produces. |
| `Store` interface: `Add`/`Get`/`List`/`Remove` (`store.go:39`) | |
| `BackendStore` (`store.go:61`) | `NewBackendStore(backend storage.Backend) (*BackendStore, error)`. |
| `ParseLine` / `Emit` | Parse an `authorized_keys`-format line into an `Entry`; render an `Entry` back to a line. |
| Typed errors (`errors.go`) | `NilInputError`, `MalformedLineError`, `NotFoundError`, `DuplicateError`, `InvalidNameError`, `StorageError`, `SerializationError`, `UnsupportedVersionError`. |

## Exported surface — `pkg/ssh/tenancy` (the server-side SSH service)

| Symbol | Contract |
|---|---|
| `Options{Storage, Resolver}` / `New(opts) (sdkssh.Client, error)` | `client.go:72-116`. `Storage` is required (`*NilInputError` otherwise) and owned: `Close` closes it, idempotently. `Resolver` is optional and unscoped; the client narrows it per partition. |
| Owner binding | `client.go:170-182`. A tenant-scoped caller owns `scope=tenant` only for `owner == identity.TenantID`, and `scope=user`/`service` only for `owner == identity.Subject`. A platform caller (`auth.IsCrossTenant`) owns every address. |
| Partition choice | `client.go:217-266`. Tenant-scoped callers: their own tenant, always. Platform callers: the tenant a `scope=tenant` owner names, else the platform (unprefixed) partition. A platform owner no tenant can have (`storage.ValidateTenantID` fails) has no partition and is refused. Tenant partitions are `tenants/<id>/` prefixes of `Storage` (`client.go:69,283-301`). |
| Backend namespace | `client.go:306-320`, `keyprovider.go:33-105`. A tenant partition's `KeyProvider` sets `KeyAttributes.TenantID` on every call, never mutating the caller's attributes; `ListKeys` returns only its tenant's keys; `Close` releases nothing (the provider is shared). A resolver that returns no provider is `*backend.BackendNotFoundError`. |
| Refusals | Reads, deletes, `Verify` and `Callback` on an address the caller does not own are served by the empty partition and wrapped in `*OwnerBindingError` (`client.go:324-346`). Writes (`Generate`, `Import`, known-hosts `Add`, authorized-keys `Add`) are answered with the empty partition's lookup of the same address and never touch a store or backend (`ops.go:38-59,135-138,152-163,237-248`). `Emit` addresses no asset and is not bound (`ops.go:297-299`). |
| Listings | `ops.go:76-92,166-182,264-280`. The listing reads the caller's partition and drops every item the caller does not own; filters never widen it. |
| Sessions / console | `ops.go:327-352`: key and host-key pins must both be owned and in one partition. `client.go:133-143`: the console binds `(KeyScope, KeyOwner)`, which addresses both. |
| Typed errors (`errors.go`) | `NilInputError`; `CallerTenantError` (a tenant-scoped identity whose tenant fails `storage.ValidateTenantID`: an internal invariant failure); `OwnerBindingError{Op, Scope, Owner, CallerTenantID, CallerSubject, Err}` — `Error()` is `Err.Error()` and `Unwrap()` is `Err`, the genuine-miss answer, so every transport's classifier maps it exactly as the miss; `EmptyPartitionError` (the empty partition answered a lookup — still a refusal, reported as internal). |

## Exported surface — `sdk/go/client/ssh` (the transport-agnostic client)

`Client` interface (`client.go:26`): `Keys() KeysClient`, `KnownHosts()
KnownHostsClient`, `AuthorizedKeys() AuthorizedKeysClient`, `Session()
SessionClient` (out of scope here — see `../ssh-agent-sessions/`),
`Console(...)` (embedded-only; out of scope here).

- `KeysClient` (`client.go:71`): `Generate`, `Import`, `Get`, `List`,
  `Delete`, `ExportPublic`, `Signer`.
- `KnownHostsClient` (`client.go:100`): `Add`, `List`, `Remove`, `Verify`,
  `Callback`.
- `AuthorizedKeysClient` (`client.go:117`): `Add`, `Get`, `List`, `Remove`,
  `Emit`, `Verify`.

`NewClientForServer(server, tlsCA, token)` dispatches to one of the embedded/
REST/gRPC/unix/QUIC/MCP implementations by URL scheme (see
architecture.md). `GenerateRequest.Backend` (`types.go:108-122`): empty
string generates a software key sealed in-process; a non-empty backend ID
generates the key on that crypto backend via `pkg/ssh/backend.Provider`, and
signing is delegated so a hardware-backed private key never leaves the
device.

## Daemon wiring (`pkg/server/server.go`)

`ensureSSHClient()` (`server.go:486-512`, `sync.Once`-guarded) is the only
place an `sdkssh.Client` is constructed for `xkmsd`. It:

1. Returns `nil` immediately if `s.xkmsService == nil` — every REST/gRPC/MCP
   SSH route is `Enabled: hasSSH` (`s.sshHandlers != nil`), so the whole
   feature is absent, not erroring, when there is no `XKMSService`.
2. Creates a `"ssh"`-prefixed `storage.Backend` view via
   `s.createStorage("ssh")` for key envelopes.
3. Builds an unscoped `sshbackend.ResolverFunc` closing over
   `s.xkmsService.LookupBackend(backendID)`.
4. Constructs `tenancy.New(tenancy.Options{Storage: sshStorage, Resolver:
   resolver})` and stores it as `s.sshClient`.

Every transport's SSH handlers hold a reference to this one client; none
constructs its own, and none performs its own owner check.

## REST/gRPC/MCP handler files (thin, transport-only)

`pkg/api/rest/handlers_ssh.go` (`SSHHandlers`), `pkg/api/grpc/service_ssh.go`
(`Service`), `pkg/api/mcp/handlers_ssh.go` (`Server`) each decode a
transport-specific request into the corresponding `sdkssh` request struct
and call the matching `s.sshClient`/`h.client` method. None re-implements
key generation, storage, verification, or owner binding logic — see architecture.md for
the one exception (gRPC's client-side `Verify`/`Emit`), which lives in the
SDK client, not the server handler.

## Testing

- Backend CN injectivity (go-xkms#1238): `pkg/ssh/keys/backend_keyid_test.go`
  covers the exact reported collision, a property test over adversarial
  owner/name fragments, a native Go fuzz target
  (`FuzzBackendKeyID_Injective`), the backend character-set/length
  constraints, and the `*BackendKeyIDTooLongError` refusal.
  `pkg/ssh/tenancy/client_test.go`'s `TestBackendKeys_DistinctAddressesDoNotCollide`
  is the end-to-end regression: it generates, signs and `Get`s both
  previously-colliding addresses through the real software backend.
- Owner binding (go-xkms#1230): `pkg/ssh/tenancy/client_test.go` and
  `keyprovider_test.go` cover every operation across the owner matrix, the
  partition rules, platform reach, the per-tenant backend namespace and the
  refusal errors. Each transport repeats the attack matrix end to end —
  `pkg/api/rest/handlers_ssh_crosstenant_test.go`,
  `pkg/api/grpc/service_ssh_crosstenant_test.go`,
  `pkg/api/mcp/handlers_ssh_crosstenant_test.go`: tenant A's alice against
  tenant B's assets, against bob's, and against the same-subject alice of
  tenant B. Every read must equal the genuine-miss response byte for byte and
  leave the asset in place; no listing may show it; no write may land.
  `pkg/api/rest/server_ssh_authz_test.go` pins each REST route's permission.
- Unit: `make test-ssh` runs `pkg/ssh/...`. Also
  `go test -tags codec_json ./xkey/pkg/gui/services/ -run SSH` and the SDK +
  gRPC-service SSH test files (`sdk/go/client/ssh/*_test.go`,
  `pkg/api/grpc/service_ssh_test.go`, `pkg/api/rest/handlers_ssh_test.go`,
  `pkg/api/mcp/handlers_ssh_test.go`).
- Integration (devcontainer only, per this repo's testing rules):
  `make integration-test-api-ssh` drives the CLI against a dockerized
  `xkmsd` over embedded/REST/gRPC/QUIC/MCP/unix (generate → list → export →
  delete, plus a backend-selection check).
  `make integration-test-ssh-backends` confirms
  generate → derive public key → sign → verify on every backend: software,
  TPM 2.0 (in-process simulator), PKCS#11 (SoftHSM2), and cloud KMS (AWS via
  Floci with real signatures; GCP/Azure via self-consistent in-memory-ECDSA
  mocks) — not independently re-verified for this folder; treat the exact
  cloud-mock behavior as the legacy `../ssh/README.md`'s claim, not
  re-confirmed here.
