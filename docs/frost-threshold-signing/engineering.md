# FROST Threshold Signing — Engineering Contract

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-10-12 (#1433)

All symbols below require `-tags frost` unless noted. See
[`architecture.md`](architecture.md) for why the CLI and network-API surfaces
are independent, and for how FROST keys are scoped to tenants.

## Exported surface — `pkg/keyprovider/frost`

`FrostBackend` (`backend.go:33`) implements `types.KeyProvider`. Every
attribute-addressed method takes a `context.Context` first and names the key
by `attrs.CN` (and `attrs.TenantID`):

| Method | Contract |
|---|---|
| `NewBackend(config *Config) (*FrostBackend, error)` | `backend.go:43`. Validates and defaults the config (see below), then builds the `KeyStore` and `NonceTracker` over `Config.DAOs`. |
| `Type() types.BackendType` | `backend.go:71`. Returns `types.BackendTypeFrost` (`"frost"`). |
| `Capabilities() types.Capabilities` | `backend.go:76`. |
| `GenerateKey(ctx, attrs) (crypto.PrivateKey, error)` | `backend.go:100`. Fills missing `FrostAttributes` from the config defaults, runs `Config.DKG` (trusted dealer if nil), and stores package `ParticipantID` (`0` selects participant 1; an ID above the package count is refused). Returns a `*FrostKeyHandle`; an existing key is `ErrKeyAlreadyExists`. |
| `GetKey(ctx, attrs) (crypto.PrivateKey, error)` | `backend.go:218`. Returns a `*FrostKeyHandle`. |
| `DeleteKey(ctx, attrs) error` | `backend.go:259`. |
| `ListKeys(ctx) ([]*types.KeyAttributes, error)` | `backend.go:283`. |
| `Signer(ctx, attrs) (crypto.Signer, error)` | `backend.go:322`. Works only when the key's `MinSigners` is 1; otherwise `*ThresholdSigningNotSupportedError` (`backend.go:358-359`). |
| `Decrypter(ctx, attrs) (crypto.Decrypter, error)` | `backend.go:371`. Always fails: `ErrDecryptionNotSupported` — FROST is signing-only per RFC 9591. |
| `RotateKey(ctx, attrs) error` | `backend.go:377`. Reads the key's public metadata, deletes the key, and generates a new one with the same threshold, total, algorithm, participants and participant ID. Every participant must import a new package: the old shares no longer match. |
| `PublicKeyPackage(ctx, attrs)` | `backend.go:442`. The group public key and verification shares, read without unsealing the secret share. |
| `ImportKeyPackage(ctx, attrs, pkg)` | `backend.go:464`. Stores a dealer package. |
| `Close() error` | `backend.go:500`. |
| `GenerateNonces(keyID string) (*NoncePackage, error)` | `rounds.go:49`. Round 1: this participant's secret nonces and public commitments. Records nothing; the nonce is claimed in Round 2. |
| `SignRound(keyID string, message []byte, nonces *NoncePackage, commitments []*Commitment) (*SignatureShare, error)` | `rounds.go:158`. Round 2: with `EnableNonceTracking`, first claims the nonce (`NonceTracker.Claim`, `rounds.go:198`, see "Nonce claims" below), then produces this participant's signature share. A nonce already claimed fails with `*NonceReuseError` before any share is computed. |
| `Aggregate(keyID string, message []byte, commitments []*Commitment, shares []*SignatureShare) ([]byte, error)` | `rounds.go:329`. Combines ≥ threshold shares into the final Schnorr signature; an aggregation failure is a `*CulpritError` carrying `KeyID` and the underlying `Reason` (`rounds.go:409-412`). Its `Culprits` field is not filled in, so the error does not identify which participant sent a bad share. |
| `Verify(keyID string, message, signature []byte) error` | `rounds.go:426`. Verifies against the stored group public key. |

The round API takes the storage key ID (see "Service layer and tenancy").
The secret share and the round nonces are wiped through
`SecretKeyShare.Zeroize` (`keygen.go:103`, `enclave.Wipe`) and
`SigningNonces.Zeroize` (`nonce.go:132`).

## Configuration — `frost.Config` (`pkg/keyprovider/frost/config.go:25`)

| Field | Required | Default | Notes |
|---|---|---|---|
| `DAOs *qrdbsdk.DAOFactory` | yes | — | `ConfigError{Field: "DAOs"}` if nil (`config.go:90-91`). Serves the go-qrdb `frost` database holding every FROST entity — see "Storage" below. Nonce claims need a store with atomic writes. |
| `SecretBackend types.SealingKeyProvider` | yes | — | `ConfigError{Field: "SecretBackend"}` if nil or `!SecretBackend.CanSeal()` (`config.go:94-98`). Must implement both `types.KeyProvider` (`Type`/`Capabilities`, used by `FrostBackend`) and `types.Sealer` (`Seal`/`Unseal`/`CanSeal`) — see "Secret share sealing" below. |
| `SecretSealKeyAttributes *types.KeyAttributes` | no | `nil` | Identifies the wrapping key `SecretBackend` seals/unseals with. `nil` when the backend needs no attributes at all (only a bare test `Sealer`); a fixed `CN` names one wrapping key reused for every FROST key in the store (PKCS#11/cloud KMS/software/PKCS#8); a `CN`-less template (`Parent` only, TPM2) gets a per-key `CN` filled in — see `KeyStore.secretSealKeyAttributesFor` (`storage.go:121`). |
| `DKG KeyGenerator` | no | `NewTrustedDealer()` | See architecture.md — no other generator ships. |
| `Algorithm types.FrostAlgorithm` | no | `FrostAlgorithmEd25519` | Must be one of the five ciphersuites below or `ConfigError{Field: "Algorithm"}`. |
| `ParticipantID uint32` | no | `0` | `0` means dealer mode in `xkmsctl`; when set, must be `1..DefaultTotal`. |
| `DefaultThreshold int` | no | `2` | Must be `>= 2` and `<= 255`. |
| `DefaultTotal int` | no | `3` | Must be `>= DefaultThreshold` and `<= 255`. |
| `Participants []string` | no | — | If set, length must equal `DefaultTotal`. |
| `EnableNonceTracking bool` | no | `true` | Zero value is `false`; `DefaultConfig()` sets it `true` explicitly. Constructing `Config{}` literally without setting this field leaves nonce tracking **off** — always set it explicitly, or start from `DefaultConfig()`. |

`(*Config).Validate()` (`config.go:89`) runs these checks and fills defaults for
`Algorithm`/`DefaultThreshold`/`DefaultTotal` (mutates the receiver).
`DefaultConfig()` returns a `*Config` with `Algorithm`, `DefaultThreshold`,
`DefaultTotal`, and `EnableNonceTracking` pre-set; callers still must supply
`DAOs` and `SecretBackend`.

## Storage — go-qrdb entities (`pkg/keyprovider/frost/entity.go`)

Every FROST record is a go-qrdb entity in the `frost` database
(`DatabaseName`, `entity.go:30`), reached through DAOs built by
`pkg/dao.New` over `Config.DAOs`. Each entity's ID is a hash of its natural
key, its `Name`:

| Entity | Entity type | Natural key | Holds |
|---|---|---|---|
| `FrostKey` | `frost_keys` | `<keyID>` | `KeyMetadata` and the group public key. |
| `FrostShare` | `frost_verification_shares` | `<keyID>/<index>` | One participant's public verification share. |
| `FrostSecretShare` | `frost_secret_shares` | `<keyID>/<participantID>` | This node's secret share, only as the `types.SealedData` envelope `SecretBackend` sealed it into. No field ever holds it unsealed. |
| `FrostNonce` | `frost_nonces` | `<keyID>/<hex SHA-256 of the commitment>` | A claimed nonce: key ID, participant ID, session ID. Commitments are public, so the record holds nothing secret. |

Storage failures are `*StoreError{Op, Key, Err}` (`errors.go`), which
unwraps to the store's own error. `NewKeyStore` and `NewNonceTracker` return
`ErrNilDAOFactory` for a nil factory, and `*StoreError{Op: "open"}` when the
`frost` database cannot be opened. Data written by the earlier file-path
layout is not read; there is no migration.

### Nonce claims (`pkg/keyprovider/frost/nonce.go`)

`NonceTracker.Claim` (`nonce.go:64`) writes the `FrostNonce` with the DAO's
`SaveIfAbsent`: one atomic create, with no read-then-write for two signers to
race through. Exactly one claim of a nonce succeeds, across every goroutine,
process and node sharing the datastore. Every other claim returns
`*NonceReuseError`, which unwraps to `ErrNonceAlreadyUsed`. A store failure
returns `*StoreError{Op: "claim nonce"}`. The outcome of that claim is
unknown, so `SignRound` produces no share. `DeleteKeyNonces`
(`nonce.go:83`) removes a key's claims when the key is deleted, and joins
every failed delete into its error.

Per key, `types.FrostAttributes` (`pkg/types/types.go:769`) carries
`Threshold`, `Total`, `Algorithm`, `Participants`, `ParticipantID` and,
after generation, `GroupPublicKey`. `GenerateKey` fills any zero field from
the `Config` defaults.

## Key generation contract (`pkg/keyprovider/frost/keygen.go`)

`Config.DKG` takes any `KeyGenerator` (`keygen.go:127`):

```go
type KeyGenerator interface {
    Generate(config FrostConfig) ([]*KeyPackage, *PublicKeyPackage, error)
}
```

`Generate` returns **every** participant's package, in participant-ID
order, plus the shared public package. `GenerateKey` keeps only the package
for its own `ParticipantID`. A custom generator for a real DKG must return
the packages this participant can obtain in the same shape.

| Type | Where | Fields |
|---|---|---|
| `FrostConfig` | `keygen.go:31` | `Threshold`, `Total`, `Algorithm`, `Participants`, `ParticipantID`. `Validate` (`keygen.go:49`): threshold ≥ 2, total ≥ threshold, both ≤ 255, `Participants` length equals total when set, algorithm known. |
| `KeyPackage` | `keygen.go:72` | `ParticipantID`, `SecretShare *SecretKeyShare` (`Value []byte`), `GroupPublicKey`, `VerificationShares map[uint32][]byte`, `MinSigners`, `MaxSigners`, `Algorithm`. |
| `PublicKeyPackage` | `keygen.go:108` | `GroupPublicKey`, `VerificationShares`, `MinSigners`, `MaxSigners`, `Algorithm`. |

`TrustedDealer` (`keygen.go:139`, `NewTrustedDealer` `:142`) is the only
generator that ships. Its `Generate` (`keygen.go:148`) runs go-frost's
dealer with identifiers `1..Total` and maps go-frost's verification-share
indices back to those participant IDs. Because `FrostConfig.Validate`
refuses a threshold below 2, every key generated through it needs the round
API; `Signer` cannot serve it.

## xkmsd configuration (`backends.frost`)

`xkmsd` builds `frost.Config` from YAML (`pkg/config/frost.go:49`, wired by
`Server.initFrostBackend`, `pkg/server/backend_frost.go:40`). The FROST
entities go to the node's `frost` database through its DAO factory; there is
no path to configure.

```yaml
backends:
  frost:
    enabled: true
    secret_backend: tpm2
    algorithm: FROST-Ed25519-SHA512
    default_threshold: 2
    default_total: 3
```

| Key | Rule (`FrostConfig.Validate`, `pkg/config/frost.go:92`) |
|---|---|
| `secret_backend` | Required. One of `software`, `pkcs8`, `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault` (`frost.go:29`), and that `backends.*` section must be configured and enabled (`pkg/config/config.go:1774`, `enabledBackendNamed`, `frost.go:140`). |
| `algorithm` | Defaults to `FROST-Ed25519-SHA512`; must be one of the five ciphersuites. |
| `default_threshold` | Defaults to `2`; must be 2–255. |
| `default_total` | Defaults to `3`; must be ≤ 255 and ≥ `default_threshold`. |

A violation is a `*FrostConfigError{Field, Message}` at startup. At
construction, a `secret_backend` that is missing or is not a
`types.SealingKeyProvider` is `ErrFrostSecretBackendUnavailable`. `xkmsd`
always enables nonce tracking and sets no `DKG`, `ParticipantID` or
`Participants`: those are per-request (`FrostAttributes`) or embedder-only.

## Secret share sealing (`pkg/keyprovider/frost/storage.go`, `wrapkey.go`)

Each participant's FROST secret key share is protected by the secret
backend's own `types.Sealer` implementation — TPM2 PCR-bound seal under the
Platform SRK, PKCS#11/cloud KMS AES-256-GCM envelope encryption under a
provisioned symmetric key, or software/PKCS#8's HKDF-derived AES-GCM key
(go-xkms#841). There is no `SealData`/`GenerateKey`-based opaque-secret path
on any backend; `KeyStore` never calls `SecretBackend.GenerateKey` or
`GetKey` for the secret share.

- `KeyStore.StoreKeyPackage` (`storage.go:175`) calls
  `secretBackend.Seal(ctx, pkg.SecretShare.Value, ks.secretSealOptions(keyID))`
  before writing anything, then saves the `FrostKey`, the `FrostShare`s and
  the `FrostSecretShare` holding the resulting `types.SealedData`. Sealing is
  what makes storing the envelope beside the public components safe. A seal
  failure stores nothing; a later save failure deletes what was written.
- `KeyStore.LoadKeyPackage` (`storage.go:224`) reads that envelope back and
  calls `secretBackend.Unseal(ctx, &secret.Sealed, ks.secretUnsealOptions(keyID))`.
  Its return value is used directly as the secret share bytes.
- `KeyStore.DeleteKey` (`storage.go:315`) deletes the `FrostSecretShare`
  first, then the verification shares, then the `FrostKey` last, so a
  partial failure leaves the key record behind and a retry can finish.

### Wrapping-key attributes (`pkg/keyprovider/frost/wrapkey.go`)

| Function | Backend family | Notes |
|---|---|---|
| `SymmetricSecretSealKeyAttributes(store types.StoreType)` (`wrapkey.go:42`) | PKCS#11, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault | `CN: SecretSealKeyCN`, `KeyType: KeyTypeEncryption`, `SymmetricAlgorithm: SymmetricAES256GCM`. Provision with `seal.EnsureSealKey`. |
| `AsymmetricSecretSealKeyAttributes(store types.StoreType)` (`wrapkey.go:60`) | software, PKCS#8 | `CN: SecretSealKeyCN`, `KeyAlgorithm: x509.Ed25519`. These backends' `Seal` loads an existing private key via `GetKey` and derives an AES key from it (HKDF); provision with `seal.EnsurePrivateSealKey`. |
| `TPM2SecretSealKeyAttributes(psrkAttrs *types.KeyAttributes)` (`wrapkey.go:80`) | TPM2 | `Parent: psrkAttrs`, no `CN` — a template. TPM2 seals directly under the Platform SRK and needs no provisioning step; `KeyStore` fills in a per-FROST-key `CN` (`"frost-secret:" + keyID`, `secretSealCN`, `storage.go:136`) so each key gets its own TPM-sealed object identity instead of every key's `Seal` overwriting one shared slot. |

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

### xkmsctl's local store (`cmd/xkmsctl/frost.go`, `frost_passphrase.go`)

`xkmsctl frost` composes the same pieces locally, with a passphrase instead
of hardware protecting the wrapping key (go-xkms#1324):

| Step | Code | Behaviour |
|---|---|---|
| Directories | `frostStoreDirs` (`frost.go:1306`) | `MkdirAll` of `<key-dir>/frost/{public,secrets}` with `0700`, then `Chmod 0700` on the three FROST directories. `<key-dir>` is only created, never re-moded. |
| Entity store | `newFrostBackend` (`frost.go:1456`) | The FROST entities live in `<key-dir>/frost/public`: a file `storage.Backend` adapted by `client.NewBackendDAOFactory` into the `Config.DAOs` factory. The file backend's atomic `PutIfAbsent` backs the nonce claim. |
| Backend check | `openFrostLocalStore` (`frost.go:1364`) | `--backend` must be `software`; anything else is `ErrFrostWrapBackendUnsupported`. |
| Passphrase | `resolveFrostPassphrase` (`frost_passphrase.go:65`) | `--passphrase-stdin`, then `--passphrase-file`, then `XKMS_FROST_PASSPHRASE`; one trailing line ending trimmed; held as a `client.Password` (locked go-enclave memory enclave); raw bytes wiped. No flag accepts the value. |
| Wrapping-key backend | `newFrostWrapKeyProvider` (`frost.go:1413`) | `client.NewPKCS8Backend` over `<key-dir>/frost/secrets` with `AllowPlaintextKeys` false. |
| Wrapping key | `ensureFrostWrapKey` (`frost.go:1435`) | `AsymmetricSecretSealKeyAttributes(StoreSoftware)` with `Password` set, provisioned by `EnsurePrivateSealKey`, so the key is written as encrypted PKCS#8 (PBES2). A decode failure (`client.ErrPKCS8KeyDecodingFailed`) is `ErrFrostPassphraseRejected`; any other failure is `ErrProvisionFrostSealKeyFailed`. |
| Public verbs | `openFrostPublicBackend` (`frost.go:1334`) | Same PKCS#8 backend, no passphrase, no provisioning: a seal or unseal through it fails to decode the wrapping key. `info` reads `PublicKeyPackage` rather than unsealing. |

`import` stores through `FrostBackend.ImportKeyPackage`, so it shares this
wiring rather than building its own `KeyStore`.

### Dealer package encryption (`cmd/xkmsctl/frost_export.go`, go-xkms#1337)

Dealer-mode `keygen` encrypts each participant's package to a recipient key
that participant created, so only they can import it. The package is a JWE
(RFC 7516) built with the SDK's existing `NewJWEEncrypter`/`NewJWEDecrypter`
(`pkg/encoding/jwe`): `ECDH-ES+A256KW` key management to an ECDSA P-256
recipient key and `A256GCM` content encryption. All four primitives (P-256
ECDH, the RFC 7518 Concat KDF over SHA-256, AES Key Wrap, AES-GCM) are FIPS
140-3 approved, so the export works under `GODEBUG=fips140=only`; an
X25519/age-style box would not.

| Step | Code | Behaviour |
|---|---|---|
| Recipient key | `frostRecipientKeyAttributes`, `ensureFrostRecipientKey`, `loadFrostRecipientKey` (`frost_export.go:66`, `:79`, `:94`) | ECDSA P-256, CN `frost-share-recipient`, `KeyTypeEncryption`, `StoreSoftware`, `Password` = the FROST passphrase, in the same PKCS#8 backend as the wrapping key. `ensure` provisions via `EnsurePrivateSealKey`; `load` never creates (`ErrFrostRecipientKeyMissing`). A decode failure is `ErrFrostPassphraseRejected`. |
| Recipient ID | `frostRecipientID` (`frost_export.go:123`) | RFC 7638 SHA-256 JWK thumbprint (`client.JWKThumbprintSHA256`). It is the JWE `kid` and what `frost recipient` prints for out-of-band confirmation. |
| Dealer input | `parseFrostRecipients` (`frost_export.go:149`) | `--recipient <id>=<pem>` for every ID `1..total`. Refuses a bad spec, an out-of-range, duplicate or missing ID, a non-P-256 key, and one key given for two participants. Runs before generation. |
| Encrypt | `encryptKeyPackageExport` (`frost_export.go:193`) | JSON-encodes the `KeyPackageExport` (unchanged inner format), encrypts it with `kid` in the protected header, wipes the plaintext buffer. |
| Decrypt | `decryptKeyPackageExport` (`frost_export.go:226`) | Empty `package` is `ErrFrostPackageNotEncrypted`; a `kid` other than this store's recipient ID is `ErrFrostPackageRecipientMismatch`; a failed GCM open is `ErrFrostPackageDecryptFailed`. |
| Import | `readFrostPackage` (`frost.go:542`) | Reads the file, loads the recipient key, decrypts. `import` stores nothing until this succeeds. |

The exported file is `EncryptedKeyPackageExport`: `key_id`, `participant_id`
and `participant_name` in the clear as routing labels, and `package`, the
JWE compact serialization. `import` reads every stored value from the
decrypted package, never from the clear labels. The protected header,
including `kid`, is authenticated as GCM additional data.

The recipient's public key must reach the dealer with integrity. JWE
provides confidentiality to whichever key the dealer was given; confirming
`recipient_id` over a second channel is the operator's control against a
substituted key.

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
`ErrInvalidCommitment`, `ErrInvalidShare`, `ErrThresholdSigningNotSupported`,
`ErrInvalidConfig`, `ErrInvalidAttributes`, `ErrUnsupportedAlgorithm`,
`ErrInvalidParticipant`, `ErrDKGFailed`, `ErrAggregationFailed`,
`ErrDecryptionNotSupported`. Detail types (`KeyNotFoundError`, `KeyIDError`,
`ShareNotFoundError`, `NonceReuseError`, `CulpritError`, `ConfigError`,
`AlgorithmError`, `ThresholdSigningNotSupportedError`) carry the offending
value and unwrap to a sentinel — for example `NonceReuseError` to
`ErrNonceAlreadyUsed` and `CulpritError` to `ErrInvalidShare`
(`errors.go:146`, `:164`).

## Daemon backend registration (`pkg/xkms/register_frost.go`)

`init()` calls `RegisterBackend(BackendFROST)` and
`RegisterBackendFactory(BackendFROST, newFROSTKeyProvider)`. The factory
(`register_frost.go:53`) builds a software-backed `frost.Config` (a `pkcs8`
`SecretBackend`, and a `DAOs` factory over an in-memory go-qrdb KV store) from a
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
memory and the medium the `DAOs` store and the `SecretBackend`'s
`KeyStorage` ultimately write to.

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

## Service layer and tenancy (network API only, go-xkms#1231)

The REST, gRPC and MCP FROST handlers are thin adapters over
`pkg/xkms/servicer_frost.go`. None of them touches a `FrostBackend` itself.

| Symbol | Where | Contract |
|---|---|---|
| `XKMSService.FrostGenerateKey` | `pkg/xkms/servicer_frost.go:253` | Participant mode stores the key for the caller's tenant; dealer mode returns every package and stores nothing. Both require a registered FROST backend. |
| `XKMSService.FrostImportKey` | `servicer_frost.go:364` | Imports one package into the caller's tenant, replacing only that tenant's key of the same ID. |
| `XKMSService.FrostListKeys` | `servicer_frost.go:406` | The caller's tenant's keys, ordered by key ID; every tenant's for a platform-scoped caller. Describes each key from its public package (`FrostBackend.PublicKeyPackage`, `pkg/keyprovider/frost/backend.go:442`) without unsealing the secret share. |
| `XKMSService.FrostGetKey` / `FrostDeleteKey` | `servicer_frost.go:450`, `:484` | Resolve the key ID inside the caller's tenant. |
| `XKMSService.FrostGenerateNonces` / `FrostSignRound` / `FrostAggregate` / `FrostVerify` | `servicer_frost.go:518`, `:535`, `:583`, `:620` | Resolve the key ID inside the caller's tenant, then drive the round API by storage key ID. `FrostVerify` reports a signature that does not verify as `Valid: false` with a `Reason`, not as an error. |
| `frost.StorageKeyID(tenantID, keyID)` | `pkg/keyprovider/frost/tenant.go:46` | `keyID` for a platform key, `tenantID:keyID` for a tenant's key; validates both halves. The round API (`GenerateNonces`, `SignRound`, `Aggregate`, `Verify`) takes this ID and re-validates it (`validateStorageKeyID`, `tenant.go:73`). |
| `FrostBackend.ImportKeyPackage` | `pkg/keyprovider/frost/backend.go:464` | Stores a dealer package under the key `attrs` names, stamping `attrs.TenantID`. |
| `KeyMetadata.TenantID` | `pkg/keyprovider/frost/storage.go:38` | The owning tenant, empty for a platform key; `ListKeys` reports it as `KeyAttributes.TenantID`. |

Invariants:

- The tenant comes from the authenticated identity (`frostTenant`,
  `servicer_frost.go:193`), never from a request field. A platform-scoped
  caller (no identity, or the system tenant) is the platform namespace.
- Every attribute-addressed `FrostBackend` method (`GenerateKey`, `GetKey`,
  `DeleteKey`, `Signer`, `RotateKey`, `ImportKeyPackage`,
  `PublicKeyPackage`) derives the storage path from `attrs.TenantID` and
  `attrs.CN`; `FrostKeyHandle.KeyID` is the key ID, not the storage key ID.
- A key the caller's tenant does not hold is the bare `xkms.ErrKeyNotFound`
  (`frostKeyError`, `servicer_frost.go:231`), whether it is missing
  everywhere or held by another tenant.

Errors:

| Condition | Service error | REST | gRPC | MCP |
|---|---|---|---|---|
| Key not in the caller's tenant | `ErrKeyNotFound` | 404 | `NotFound` | `JSONRPCCodeNotFound` |
| Bad threshold/total/participant, missing field | `*ErrValidation{ErrFrostInvalidRequest}` (`servicer_frost.go:51`) | 400 | `InvalidArgument` | Invalid params |
| Key ID or tenant with `:`, `/`, `..` | `*ErrValidation{ErrInvalidKeyID}` | 400 | `InvalidArgument` | Invalid params |
| No FROST backend registered | `ErrFrostNotConfigured` (`servicer_frost.go:47`) | 500 | `Internal` | Internal error |
| No xkms service | `ErrNotInitialized` | 503 | `Unavailable` | — (the MCP server requires one) |
| Backend failure | `*ErrOperationWrap{ErrOperationFailed}` | 500 | `Internal` | Internal error |

Keys written before go-xkms#1231 carry no tenant and sit at their bare key
ID: they are platform keys, invisible to every tenant. There is no migration.

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
- `cmd/xkmsctl/frost_store_test.go` (`-tags frost`) covers the CLI's local
  store: a passphrase round trip that reopens the store and unseals the
  share; the stored wrapping key parses as a PBES2 `EncryptedPrivateKeyInfo`
  and not as plaintext PKCS#8, and no file under `secrets` contains the
  passphrase; a wrong passphrase and a pre-#1324 plaintext wrapping key are
  both `ErrFrostPassphraseRejected`; no passphrase is
  `ErrFrostPassphraseRequired` before any directory is created;
  `--backend tpm2` is `ErrFrostWrapBackendUnsupported`; every directory is
  `0700`, including pre-existing `0755` ones; the public backend reads
  public material but cannot unseal; passphrase source precedence, empty
  and unreadable sources, and flag mutual exclusion.
- `cmd/xkmsctl/frost_export_test.go` (`-tags frost`) covers dealer package
  encryption: the recipient key is stable across runs and stored as PBES2
  encrypted PKCS#8; an exported file contains the share in no encoding (hex,
  raw, base64) and has no `secret_share` field; a real dealer package
  round-trips through `readFrostPackage` and `ImportKeyPackage`; another
  participant's key, a wrong passphrase, a store with no recipient key, a
  tampered ciphertext and a plaintext package are each refused with their
  typed error; and every `--recipient` refusal in `parseFrostRecipients`.
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
  `xkmsd` with a configured `backends.frost` section. `test/integration/api/frost_parity_test.go`
  (`//go:build integration && frost`) drives `xkmsctl frost keygen` with
  `--transport embedded`, exercising the CLI's local path, not the
  REST/gRPC/MCP handlers against a live daemon backend.
- Tenancy: `pkg/keyprovider/frost/tenant_test.go` (storage key IDs, per-tenant
  namespaces, import, round-API validation), `pkg/xkms/servicer_frost_test.go`
  (service-level cross-tenant refusal equals a genuine miss, listing, import,
  a full 2-of-3 signature inside a tenant), and one cross-tenant suite per
  transport: `pkg/api/rest/handlers_frost_crosstenant_test.go`,
  `pkg/api/grpc/service_frost_crosstenant_test.go`,
  `pkg/api/mcp/handlers_frost_crosstenant_test.go`. Each compares, for every
  key-naming route, tenant A naming tenant B's key against the same key ID in
  a deployment where no tenant holds it, then proves B's key survived.
- The REST handler unit tests
  (`pkg/api/rest/handlers_frost_real_test.go`) inject a hand-built
  `frost.NewBackend(...)`-backed fake `xkms.Backend` directly into the
  `HandlerContext`'s registry — proof the handlers work once a backend is
  present, not that `xkmsd` can produce one from configuration.
- The "FROST not compiled in" side: every transport's `frost` verbs, and
  `Server.initFrostBackend`, carry a `//go:build !frost` stub
  (`pkg/api/rest/handlers_frost_stub.go`, `pkg/api/mcp/handlers_frost_stub.go`,
  `pkg/api/grpc/service_frost_stub.go`, `pkg/server/backend_frost_stub.go`)
  that refuses cleanly instead of the real implementation. Its matching test
  (`*_frost_stub_test.go` beside each) only builds without the `frost` tag,
  so `make test`'s normal lane — which always carries `frost` — never
  compiles it (go-xkms#1249). `make test-nofrost` runs those four packages
  under `TEST_TAGS` minus `frost` and is wired into `make test`, so the stub
  build is exercised in CI on every full-tier run.
