# SSH Keys, Known Hosts & Authorized Keys — Engineering Contract

> **Status: NORMATIVE** · Feature: `ssh-keys` · Repo: `go-xkms` · Last verified: 2026-09-24

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
| Typed errors (`errors.go`) | `NilInputError`, `UnsupportedAlgorithmError`, `InvalidKeySizeError`, `PassphraseRequiredError`, `PEMParseError`, `KeyMaterialError`, `KeyNotFoundError`, `StorageError`, `SerializationError`, `ClosedSignerError`. |

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

`ensureSSHClient()` (`server.go:417`, `sync.Once`-guarded) is the only place
an `sdkssh.Client` is constructed for `xkmsd`. It:

1. Returns `nil` immediately if `s.xkmsService == nil` — every REST/gRPC/MCP
   SSH route is `Enabled: hasSSH` (`s.sshHandlers != nil`), so the whole
   feature is absent, not erroring, when there is no `XKMSService`.
2. Creates a `"ssh"`-prefixed `storage.Backend` view via
   `s.createStorage("ssh")` for key envelopes.
3. Builds a `sshbackend.ResolverFunc` closing over
   `s.xkmsService.LookupBackend(backendID)`.
4. Constructs `sdkssh.NewEmbedded(EmbeddedOptions{Backend: sshStorage,
   BackendProvider: provider})` and stores it as `s.sshClient`.

Every transport's SSH handlers hold a reference to this one client; none
constructs its own.

## REST/gRPC/MCP handler files (thin, transport-only)

`pkg/api/rest/handlers_ssh.go` (`SSHHandlers`), `pkg/api/grpc/service_ssh.go`
(`Service`), `pkg/api/mcp/handlers_ssh.go` (`Server`) each decode a
transport-specific request into the corresponding `sdkssh` request struct
and call the matching `s.sshClient`/`h.client` method. None re-implements
key generation, storage, or verification logic — see architecture.md for
the one exception (gRPC's client-side `Verify`/`Emit`), which lives in the
SDK client, not the server handler.

## Testing

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
