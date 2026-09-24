# FROST Threshold Signing — Engineering Contract

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-24

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
| `SecretBackend types.KeyProvider` | yes | — | `ConfigError{Field: "SecretBackend"}` if nil. |
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
(`register_frost.go:42`) builds a software-backed `frost.Config` (a `pkcs8`
`SecretBackend`, an in-memory `PublicStorage`) from a
`map[string]interface{}` with three optional keys: `"threshold"` (int),
`"total"` (int), `"participant_id"` (int). This factory is reachable only
through `xkms.AutoInitialize`/direct library embedding — **`xkmsd` never
calls it**; see architecture.md for the missing `pkg/server`/`pkg/config`
wiring.

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
  errors, keygen, nonce, rounds, signer, storage — 687+ lines in
  `backend_test.go` alone). Run with `go test -tags frost ./pkg/keyprovider/frost/...`.
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
