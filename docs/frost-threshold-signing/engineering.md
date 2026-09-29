# FROST Threshold Signing — Engineering Contract

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-28

All symbols below require `-tags frost` unless noted. See
[`architecture.md`](architecture.md) for why the CLI and network-API surfaces
are independent, and for why the network surface has no supported way to be
enabled on a stock `xkmsd` today.

## Exported surface — `pkg/keyprovider/frost`

`FrostBackend` (`backend.go:32`) implements `types.KeyProvider`:

| Method | Contract |
|---|---|
| `NewBackend(config *Config) (*FrostBackend, error)` | `config.go:70`. Validates and defaults the config (see below), then constructs. |
| `Type() types.BackendType` | Returns `types.BackendTypeFrost` (`"frost"`). |
| `Capabilities() types.Capabilities` | `backend.go:104`. |
| `GenerateKey(ctx, attrs *types.KeyAttributes) (crypto.PrivateKey, error)` | `backend.go:128`. Trusted-dealer generation (or `Config.DKG` if set) for `attrs.FrostAttributes`. |
| `GetKey(ctx, attrs) (crypto.PrivateKey, error)` | `backend.go:245`. Returns a `*FrostKeyHandle`. |
| `DeleteKey(ctx, attrs) error` | `backend.go:286`. |
| `ListKeys(ctx) ([]*types.KeyAttributes, error)` | `backend.go:309`. |
| `Signer(ctx, attrs) (crypto.Signer, error)` | `backend.go:347`. Works only when `attrs.FrostAttributes.Threshold == 1`; otherwise returns `ErrThresholdSigningNotSupported`. |
| `Decrypter(ctx, attrs) (crypto.Decrypter, error)` | `backend.go:396`. Always fails: `ErrDecryptionNotSupported` — FROST is signing-only per RFC 9591. |
| `RotateKey(ctx, attrs) error` | `backend.go:402`. |
| `Close() error` | `backend.go:463`. |
| `GenerateNonces(keyID string) (*NoncePackage, error)` | Round 1: produces this participant's signing nonces + commitments; records them against `EnableNonceTracking`. |
| `SignRound(keyID string, message []byte, nonces *NoncePackage, commitments []*Commitment) (*SignatureShare, error)` | Round 2: produces this participant's signature share for a session keyed by `(keyID, message)`. |
| `Aggregate(keyID string, message []byte, commitments []*Commitment, shares []*SignatureShare) ([]byte, error)` | Combines ≥ threshold shares into the final Schnorr signature. |
| `Verify(keyID string, message, signature []byte) error` | Verifies against the stored group public key. |

## Configuration — `frost.Config` (`pkg/keyprovider/frost/config.go:24`)

| Field | Required | Default | Notes |
|---|---|---|---|
| `PublicStorage storage.Backend` | yes | — | `ConfigError{Field: "PublicStorage"}` if nil. |
| `SecretBackend types.SealingKeyProvider` | yes | — | `ConfigError{Field: "SecretBackend"}` if nil or `!SecretBackend.CanSeal()` (`config.go:73-76`). Must implement both `types.KeyProvider` (`Type`/`Capabilities`, used by `FrostBackend`) and `types.Sealer` (`Seal`/`Unseal`/`CanSeal`) — see "Secret share sealing" below. |
| `SecretSealKeyAttributes *types.KeyAttributes` | no | `nil` | Identifies the wrapping key `SecretBackend` seals/unseals with. `nil` when the backend needs no attributes at all (only a bare test `Sealer`); a fixed `CN` names one wrapping key reused for every FROST key in the store (PKCS#11/cloud KMS/software/PKCS#8); a `CN`-less template (`Parent` only, TPM2) gets a per-key `CN` filled in — see `KeyStore.secretSealKeyAttributesFor` (`storage.go:125`). |
| `DKG KeyGenerator` | no | `NewTrustedDealer()` | See architecture.md — no other generator ships. |
| `Algorithm types.FrostAlgorithm` | no | `FrostAlgorithmEd25519` | Must be one of the five ciphersuites below or `ConfigError{Field: "Algorithm"}`. |
| `ParticipantID uint32` | no | `0` | `0` means dealer mode in `xkmsctl`; when set, must be `1..DefaultTotal`. |
| `DefaultThreshold int` | no | `2` | Must be `>= 2` and `<= 255`. |
| `DefaultTotal int` | no | `3` | Must be `>= DefaultThreshold` and `<= 255`. |
| `Participants []string` | no | — | If set, length must equal `DefaultTotal`. |
| `NonceStorage storage.Backend` | no | `PublicStorage` | |
| `EnableNonceTracking bool` | no | `true` | Zero value is `false`; `DefaultConfig()` sets it `true` explicitly. Constructing `Config{}` literally without setting this field leaves nonce tracking **off** — always set it explicitly, or start from `DefaultConfig()`. |

`(*Config).Validate()` runs these checks and fills defaults for
`Algorithm`/`DefaultThreshold`/`DefaultTotal` (mutates the receiver).
`DefaultConfig()` returns a `*Config` with `Algorithm`, `DefaultThreshold`,
`DefaultTotal`, and `EnableNonceTracking` pre-set; callers still must supply
`PublicStorage` and `SecretBackend`.

## Secret share sealing (`pkg/keyprovider/frost/storage.go`, `wrapkey.go`)

Each participant's FROST secret key share is protected by the secret
backend's own `types.Sealer` implementation — TPM2 PCR-bound seal under the
Platform SRK, PKCS#11/cloud KMS AES-256-GCM envelope encryption under a
provisioned symmetric key, or software/PKCS#8's HKDF-derived AES-GCM key
(go-xkms#841). There is no `SealData`/`GenerateKey`-based opaque-secret path
on any backend; `KeyStore` never calls `SecretBackend.GenerateKey` or
`GetKey` for the secret share.

- `KeyStore.StoreKeyPackage` (`storage.go:176`) calls
  `secretBackend.Seal(ctx, pkg.SecretShare.Value, ks.secretSealOptions(keyID))`
  and persists the resulting `types.SealedData`, JSON-marshaled, in
  `PublicStorage` at `frost/keys/<keyID>/secret_share.json`
  (`secretShareFile`, `storage.go:45-50`). Sealing is what makes storing the
  envelope in the same (unencrypted-at-rest) storage as the public
  components safe.
- `KeyStore.LoadKeyPackage` (`storage.go:231`) reads that envelope back and
  calls `secretBackend.Unseal(ctx, &sealed, ks.secretUnsealOptions(keyID))`.
  Its return value is used directly as the secret share bytes — no type
  assertion, since `Unseal` already returns `[]byte`.
- `KeyStore.DeleteKey` (`storage.go:372`) deletes `secret_share.json` from
  `PublicStorage` first (in place of the old `SecretBackend.DeleteKey`
  call), then the verification shares and group public key, then metadata
  last, preserving the original resumable-on-partial-failure ordering.

### Wrapping-key attributes (`pkg/keyprovider/frost/wrapkey.go`)

| Function | Backend family | Notes |
|---|---|---|
| `SymmetricSecretSealKeyAttributes(store types.StoreType)` (`wrapkey.go:42`) | PKCS#11, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault | `CN: SecretSealKeyCN`, `KeyType: KeyTypeEncryption`, `SymmetricAlgorithm: SymmetricAES256GCM`. Provision with `seal.EnsureSealKey`. |
| `AsymmetricSecretSealKeyAttributes(store types.StoreType)` (`wrapkey.go:60`) | software, PKCS#8 | `CN: SecretSealKeyCN`, `KeyAlgorithm: x509.Ed25519`. These backends' `Seal` loads an existing private key via `GetKey` and derives an AES key from it (HKDF); provision with `seal.EnsurePrivateSealKey`. |
| `TPM2SecretSealKeyAttributes(psrkAttrs *types.KeyAttributes)` (`wrapkey.go:77`) | TPM2 | `Parent: psrkAttrs`, no `CN` — a template. TPM2 seals directly under the Platform SRK and needs no provisioning step; `KeyStore` fills in a per-FROST-key `CN` (`"frost-secret:" + keyID`, `secretSealCN`, `storage.go:140`) so each key gets its own TPM-sealed object identity instead of every key's `Seal` overwriting one shared slot. |

`SecretSealKeyCN = "xkms-frost-wrap"` (`wrapkey.go:35`) is distinct from
`seal.SealKeyCN` (`"xkms-barrier-seal"`), the barrier's own wrapping key, so
a backend serving both roles (e.g. TPM2 as both a barrier hardware strategy
and `backends.frost.secret_backend`) never shares a single key across the
two roles.

### Provisioning (`pkg/server/backend_frost.go`, `pkg/seal/cloud_provision.go`)

`Server.ensureFrostSecretSealKey` (`backend_frost.go`, added for #841)
dispatches on `backends.frost.secret_backend`'s name and provisions
(idempotently) the wrapping key before constructing `frost.Config`:

| `secret_backend` | Provisioning |
|---|---|
| `tpm2` | None — `frost.TPM2SecretSealKeyAttributes(backend.SRKAttributes())`. |
| `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault` | `seal.EnsureSealKey(ctx, <matching StrategyID>, provider, attrs)` — the same idempotent check-and-skip (`GetSymmetricKey`/`GenerateSymmetricKey`) the barrier's hardware seal strategies use (go-xkms#757). |
| `software`, `pkcs8` | `seal.EnsurePrivateSealKey(ctx, provider, attrs)` (`pkg/seal/cloud_provision.go`) — the asymmetric counterpart to `EnsureSealKey`: `GetKey`-then-`GenerateKey` check-and-skip for a backend whose `Seal` derives its wrapping key from an existing private key rather than a symmetric primitive. |

`pkg/xkms/register_frost.go`'s `newFROSTKeyProvider` factory (see below)
provisions its `pkcs8` secret backend's wrapping key the same way, inline.

## Ciphersuites (`pkg/keyprovider/frost/ciphersuite.go`)

`ListSupportedAlgorithms()` (`ciphersuite.go:184`) returns exactly these five
`types.FrostAlgorithm` values (`pkg/types/types.go:656-672`), all RFC 9591:

| Constant | Wire value | Curve / hash |
|---|---|---|
| `types.FrostAlgorithmEd25519` | `FROST-Ed25519-SHA512` | Ed25519 / SHA-512 — default |
| `types.FrostAlgorithmRistretto255` | `FROST-ristretto255-SHA512` | ristretto255 / SHA-512 |
| `types.FrostAlgorithmEd448` | `FROST-Ed448-SHAKE256` | Ed448 / SHAKE256 |
| `types.FrostAlgorithmP256` | `FROST-P256-SHA256` | NIST P-256 / SHA-256 |
| `types.FrostAlgorithmSecp256k1` | `FROST-secp256k1-SHA256` | secp256k1 / SHA-256 |

`GetCiphersuite`, `GetSignatureSize`, `GetPublicKeySize`, `GetScalarSize`, and
`GetAlgorithmInfo` (`ciphersuite.go:29-184`) map each constant to the
underlying `go-frost` ciphersuite and its wire sizes.

## Errors (`pkg/keyprovider/frost/errors.go`)

Sentinel `error` values (not typed structs) for the common cases:
`ErrBackendClosed`, `ErrKeyNotFound`, `ErrKeyAlreadyExists`,
`ErrInsufficientShares`, `ErrNonceAlreadyUsed` (catastrophic if ignored —
reuse recovers the key), `ErrNonceNotFound`, `ErrInvalidSignature`,
`ErrInvalidCommitment`, `ErrInvalidShare`, `ErrSessionNotFound`,
`ErrSessionExpired`, `ErrThresholdSigningNotSupported`, `ErrInvalidConfig`,
`ErrInvalidAttributes`, `ErrUnsupportedAlgorithm`, `ErrInvalidParticipant`,
`ErrDKGFailed`, `ErrAggregationFailed`, `ErrDecryptionNotSupported`. Detail
types (`KeyNotFoundError`, `ShareNotFoundError`, `NonceReuseError`,
`CulpritError`, `ConfigError`, `AlgorithmError`,
`ThresholdSigningNotSupportedError`) wrap a sentinel with the offending
value.

## Daemon backend registration (`pkg/xkms/register_frost.go`)

`init()` calls `RegisterBackend(BackendFROST)` and
`RegisterBackendFactory(BackendFROST, newFROSTKeyProvider)`. The factory
(`register_frost.go:53`) builds a software-backed `frost.Config` (a `pkcs8`
`SecretBackend`, an in-memory `PublicStorage`) from a
`map[string]interface{}` with four optional keys: `"threshold"` (int),
`"total"` (int), `"participant_id"` (int), and `"allow_plaintext_keys"`
(bool, default `false`). It provisions the `pkcs8` backend's Ed25519
wrapping key with `seal.EnsurePrivateSealKey` before constructing
`frost.Config`, mirroring `pkg/server`'s composition. This factory is
reachable only through `xkms.AutoInitialize`/direct library embedding —
**`xkmsd` never calls it**; `pkg/server/backend_frost.go`'s
`Server.initFrostBackend` (called from `server.go:1084`) is the config-driven
wiring `xkmsd` actually uses, and it is independent of this factory.

**`allow_plaintext_keys` (go-xkms#1237).** Before this flag existed, the
factory built its internal `pkcs8.Config` with no way to ever set
`AllowPlaintextKeys` (`register_frost.go:53-65`), so `seal.EnsurePrivateSealKey`
always failed with `pkcs8.ErrPlaintextKeyNotAllowed` — the factory could
never produce a working backend at all. It now threads
`config["allow_plaintext_keys"]` straight through to `pkcs8.Config`, the same
knob and the same fail-closed default `newPKCS8KeyProvider`
(`register_pkcs8.go:40-58`) already exposes for the standalone `pkcs8`
backend: `false` unless the caller opts in, because this in-memory,
per-process secret store has no other encryption-at-rest layer to fall back
on (unlike `pkg/server`'s `pkcs8` backend, whose plaintext permission is
derived from whether the node barrier or storage layer already encrypts the
data — see "Provisioning" above). A caller of `xkms.AutoInitialize` that
wants a durable, working FROST backend from this factory must set
`allow_plaintext_keys: true` in `BackendConfigs[xkms.BackendFROST]` and
accept that the wrapping key is only as protected as the process's own
memory and the medium `PublicStorage`/`SecretBackend`'s `KeyStorage`
ultimately write to.

## SDK re-exports (`sdk/go/frost.go`, `-tags frost`)

Type aliases only — `FrostBackend`, `FrostBackendConfig` (= `frost.Config`),
`FrostConfig`, `FrostKeyHandle`, `FrostKeyMetadata`, `FrostKeyPackage`,
`FrostSecretKeyShare`, `FrostCommitment`, `FrostNoncePackage`,
`FrostSignatureShare`, `FrostSigningCommitments`, `FrostSigningNonces`, plus
constructors `NewFrostBackend`, `NewFrostKeyStore`, `NewFrostTrustedDealer`,
and the ciphersuite constants. **There is no remote/HTTP client method for
FROST anywhere under `sdk/go/`** — grep for `/frost` under `sdk/go/*.go`
turns up only this file, and it never dials a transport. A Go program that
wants FROST over the network must call the REST/gRPC/MCP endpoints itself
(and first solve the daemon-wiring gap in architecture.md).

## Daemon-side handler lookup (network API only)

`getFrostBackend()` (`pkg/api/rest/handlers_frost.go:816`,
`pkg/api/grpc/service_frost.go:600`) iterates the daemon's registered
backends and returns the first whose `KeyProvider().Type() ==
types.BackendTypeFrost`, or a "no FROST backend configured" error. Every
REST/gRPC/MCP FROST handler calls this first; none constructs a backend
itself.

## Testing

- Unit: `pkg/keyprovider/frost/*_test.go` (backend, ciphersuite, config,
  errors, keygen, nonce, rounds, signer, storage, wrapkey — 687+ lines in
  `backend_test.go` alone). Run with `go test -tags frost ./pkg/keyprovider/frost/...`.
  A seal/unseal round trip against every whitelisted `secret_backend` is
  covered per backend, each gated behind its own build tag alongside
  `frost`: `backend_software_test.go` (software and PKCS#8, no extra tag —
  also covers restart survival and the wrong-wrap-key typed-error case),
  `backend_tpm2_sim_test.go` (`tpm_simulator`, real simulator, also covers
  distinct per-key sealed objects and a corrupted-envelope typed error),
  `backend_awskms_test.go` / `backend_gcpkms_test.go` (mocked KMS clients).
  `pkg/backend/pkcs11/frost_seal_test.go` (`pkcs11`, real SoftHSM2 token via
  the package's own `newProvisionedBackend` helper) and
  `pkg/backend/vault/frost_seal_test.go` (`vault`, the package's own
  in-process Transit engine double) live beside those backends instead,
  since their test helpers are unexported. Azure Key Vault's
  `GenerateSymmetricKey`/`GetSymmetricKey` construct a real `azsecrets`
  client unconditionally (no injectable seam — see
  `pkg/backend/azurekv/azurekv_symmetric_test.go`'s own `newLocalSymmetricKey`
  comment), so the full FROST+`azurekv` round trip is exercised by the
  emulator-backed integration suite (`test/integration/azurekv`), not a unit
  test, consistent with that package's own existing boundary.
- `pkg/xkms/register_frost_test.go` covers the `newFROSTKeyProvider` factory
  itself: fails closed with `pkcs8.ErrPlaintextKeyNotAllowed` on a nil or
  empty config (go-xkms#1237's reproduction); with
  `"allow_plaintext_keys": true`, two providers built through the factory
  (one per participant) complete a full 2-of-2 trusted-dealer keygen, nonce
  generation, signing, aggregation and verification round trip.
  `pkg/server/backend_frost_test.go`'s
  `TestInitializeBackends_FrostWithPKCS8SecretBackend_StartsCleanly` drives
  the real `Server.initializeBackends` (the same call `Server.New` makes)
  with `backends.pkcs8` and `backends.frost` both enabled and
  `secret_backend: pkcs8`, proving `xkmsd`'s own config-driven wiring starts
  cleanly with FROST enabled — independent of the factory fix above, since
  `initFrostBackend` never called that factory.
- Integration: `test/integration/frost/{backend,signing}_integration_test.go`
  construct a `frost.Backend` directly, in-process — they do not stand up an
  `xkmsd` with a configured FROST backend (there is no config surface to do
  so). `test/integration/api/frost_parity_test.go`
  (`//go:build integration && frost`) drives `xkmsctl frost keygen` with
  `--transport embedded`, exercising the CLI's local path, not the
  REST/gRPC/MCP handlers against a live daemon backend.
- The REST handler unit tests
  (`pkg/api/rest/handlers_frost_real_test.go`) inject a hand-built
  `frost.NewBackend(...)`-backed fake `xkms.Backend` directly into the
  `HandlerContext`'s registry — proof the handlers work once a backend is
  present, not that `xkmsd` can produce one from configuration.
