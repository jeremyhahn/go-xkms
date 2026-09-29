# Symmetric Encryption & AEAD — Engineering Contract

> **Status: NORMATIVE** · Feature: `symmetric-aead` · Repo: `go-xkms` · Last verified: 2026-09-29

## Exported surface — `pkg/keyprovider/symmetric`

- `NewBackend(config *Config) (types.SymmetricKeyProvider, error)`
  (`backend.go:111-157`). `Config{KeyStorage storage.Backend, Tracker
  types.AEADSafetyTracker, RNGConfig interface{}}`; `KeyStorage` is required
  (`Config.Validate`, `backend.go:100-109`), `Tracker` defaults to
  `backend.NewMemoryAEADTracker()`, `RNGConfig` defaults to
  `cryptorand.ModeAuto` through `cryptorand.NewResolver`.
- `Backend` methods matching `types.KeyProvider` plus the symmetric-specific
  ones: `Type()` (returns `types.BackendTypeSymmetric`), `Capabilities()`
  (`SymmetricEncryption: true, Signing: false, Decryption: false,
  KeyRotation: true, Import: true, Export: true`, `backend.go:164-176`),
  `DeleteKey`, `ListKeys`, `RotateKey`, `Close`,
  `GenerateSymmetricKey(ctx, attrs) (types.SymmetricKey, error)`,
  `GetSymmetricKey(ctx, attrs) (types.SymmetricKey, error)`,
  `SymmetricEncrypter(ctx, attrs) (types.SymmetricEncrypter, error)`,
  `DeriveFromSymmetricKey(ctx, attrs, params *kdf.KDFParams) ([]byte,
  error)` (`kdf.go:29-80`, answering PKCS#11 `C_DeriveKey` §5.18.5;
  deliberately does **not** require `attrs.Exportable` — deriving is not
  exporting).
- `NewAESKey(algorithm string, keyData []byte) (types.SymmetricKey, error)`
  (`aes_key.go:56-71`) validates 128/192/256-bit key sizes.
  `NewChaCha20Key(algorithm string, keyData []byte) (types.SymmetricKey,
  error)` (`chacha20_key.go`) accepts only 256-bit keys.
- `types.SymmetricEncrypter.Encrypt(plaintext []byte, opts
  *types.EncryptOptions) (*types.EncryptedData, error)` /
  `Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte,
  error)` (`backend.go:551-864`).

## Supported algorithms

| `types.SymmetricAlgorithm` constant | Wire string | Key size |
|---|---|---|
| `SymmetricAES128GCM` | `"aes128-gcm"` | 128 bits |
| `SymmetricAES192GCM` | `"aes192-gcm"` | 192 bits |
| `SymmetricAES256GCM` | `"aes256-gcm"` | 256 bits |
| `SymmetricChaCha20Poly1305` | `"chacha20-poly1305"` | 256 bits |
| `SymmetricXChaCha20Poly1305` | `"xchacha20-poly1305"` | 256 bits |

(`pkg/types/types.go:410-414`.) AES-CBC (`types.CipherModeCBC`/`CBCPad`) and
AES-ECB (`types.CipherModeECB`) are cipher **modes** selected via
`EncryptOptions.Mode`/`DecryptOptions.Mode`, not separate
`SymmetricAlgorithm` values — they require an AES-family key
(`isAESCipherAlgorithm`, `backend.go:909-919`) and are rejected for
ChaCha20/XChaCha20 keys with `ErrCBCRequiresAES`/`ErrECBRequiresAES`.

## Invariants

- **AEAD safety checks run in a fixed order and abort encryption on
  failure**: bytes-limit check, nonce resolution, nonce-uniqueness check,
  encrypt, then record the nonce (`backend.go:551-737`). For the
  random-nonce FIPS path the nonce is only observable *after* `Seal`, so the
  uniqueness check runs on the produced ciphertext's nonce and a collision
  discards that ciphertext rather than ever returning it
  (`backend.go:667-675`).
- **Every AEAD nonce on the Encrypt RPC is claimed in the process-wide
  guard.** A caller-supplied nonce is claimed before the seal, and a generated
  one after it (`pkg/xkms/servicer_crypto.go:650-677`). Both go through
  `claimAEADNonce` (`pkg/xkms/aead_nonce_guard.go:103-125`), the same function
  the AES-GCM wrap uses (`servicer_wrapkey.go:519`, `:551`), keyed by
  `aeadKeyIdentity` (`aead_nonce_guard.go:67-81`). A reuse is an
  `*ErrKeyOperation` wrapping `aead.ErrNonceReuse`, and no ciphertext is
  returned. A full guard refuses caller-supplied nonces with
  `aead.ErrNonceTrackerFull` but not generated ones
  (`aead_nonce_guard.go:144-160`). Tests:
  `pkg/xkms/servicer_crypto_nonce_test.go:120-505` (reuse, ChaCha20-Poly1305,
  concurrency, keys that predate the process, aliasing, generated-nonce
  replay, wrap/encrypt sharing, sealed keys, identity failure, full-guard
  policy, PKCS#11 end to end).
- **`aead.ErrNonceReuse` and `aead.ErrNonceTrackerFull` classify to
  `ClassAlreadyExists` / `ClassResourceExhausted` on every transport**,
  through `apierrors.AEADSentinelClasses` (`pkg/api/apierrors/tables.go`),
  consulted from `pkg/api/grpc/errors_keyops.go`'s and `pkg/api/mcp`'s
  `mapKeyOpError`, and mirrored by REST's `keyOpSentinelStatus`
  (`pkg/api/rest/errors_keyops.go`) — `409`/`AlreadyExists`/the MCP
  duplicate code for a reuse, `503`/`ResourceExhausted`/the MCP internal
  floor (with `Classified` set so the text is not withheld) for a full
  guard (go-xkms#1223). Both `Encrypt` and `WrapKeyByID` (the AES-GCM wrap)
  go through the same table. Tests: `TestMapKeyOpError_AEADNonceSentinels`
  in each of `pkg/api/grpc`, `pkg/api/mcp` and `pkg/api/rest`, plus the
  `"aead"` sub-test in each package's `TestClassification_MatchesSharedTables`.
- **A caller-supplied nonce against a backend whose encryption always
  happens remotely is refused, not silently dropped.** AWS KMS, GCP KMS,
  Vault Transit and the paired phone's symmetric `Encrypt` all manage nonce
  generation themselves and expose no parameter to override it; a non-nil
  `EncryptOptions.Nonce` is refused with `backend.ErrCallerNonceNotSupported`
  before the remote call is ever made (`pkg/backend/awskms/awskms_symmetric.go`,
  `pkg/backend/gcpkms/gcpkms.go`, `pkg/backend/vault/vault_symmetric.go`,
  `pkg/backend/phone/symmetric.go`), classified as `ClassInvalidArgument` via
  `apierrors.ImportExportSentinelClasses` — `400`/`InvalidArgument`/MCP
  Invalid params (go-xkms#1223).
- **CBC/ECB carry no AEAD safety tracking at all** — they are not AEAD
  modes, so `IncrementBytes`/`CheckNonce`/`RecordNonce` are never called on
  that path (`backend.go:556-569`, `:750-759`).
- **`Exportable` and `Sensitive` are set-once, at creation.** The persisted
  `keyMetadata` record (`metadata.go:47-68`, schema version 3) documents
  this explicitly: "Only `newKeyMetadata` may set this field to true;
  nothing downstream of key creation is permitted to widen a key from
  non-exportable to exportable." `saveKeyMetadataOrRollback`
  (`metadata.go:114-...`) deletes the just-written key blob if the metadata
  write fails, so a key is never left with material on disk and no metadata
  record.
- **CBC padding-oracle resistance is unconditional.** `unpadPKCS7`
  (`backend.go:1162-1203`) runs the same number of comparisons regardless of
  where or whether padding is invalid, and returns the single
  `ErrInvalidPadding` for every failure mode — no branch may be added whose
  timing or error value depends on *how* padding failed (Vaudenay 2002).
- **A stored, password-protected symmetric key's own wrapping is subject to
  the identical FIPS-mode GCM-construction rules** as an ordinary AEAD
  `Encrypt` call — see [`architecture.md`](architecture.md) §"GCM nonce
  modes and FIPS".

## Errors

All declared as typed sentinels in `errors.go`, never inline `fmt.Errorf`:
`ErrStorageClosed`, `ErrInvalidPassword`, `ErrUnsupportedCipherMode`,
`ErrCBCRequiresAES`, `ErrECBRequiresAES`, `ErrIVNotSupported`,
`ErrInvalidTagSize`, `ErrTagSizeNotSupported`,
`ErrArbitraryIVGCMUnavailable`, `ErrAdditionalDataNotSupported`,
`ErrInvalidIVSize`, `ErrPlaintextNotBlockAligned`,
`ErrCiphertextNotBlockAligned`, `ErrKeyMetadataNotFound`,
`ErrInvalidPadding`. `pkg/backend/errors.go` separately declares
`ErrNonceReused` and `ErrBytesLimitExceeded`, returned by the
`AEADSafetyTracker` implementation, not by this package, and
`ErrCallerNonceNotSupported` (go-xkms#1223), returned by the AWS KMS, GCP
KMS, Vault Transit and paired-phone symmetric `Encrypt` implementations when
the caller supplies a nonce those backends' remote encryption service cannot
honor.

## AEAD safety tracker — `types.AEADSafetyTracker`

Interface (`pkg/types/types.go:2751-2779`): `CheckNonce(keyID, nonce)
error`, `RecordNonce(keyID, nonce) error`, `IncrementBytes(keyID, numBytes
int64) error`, `GetBytesEncrypted(keyID) (int64, error)`,
`GetAEADOptions(keyID) (*AEADOptions, error)`, `SetAEADOptions(keyID,
*AEADOptions) error`, `ResetTracking(keyID) error`.

`types.AEADOptions{NonceTracking, BytesTracking, BytesTrackingLimit,
NonceSize bool/bool/int64/int}`; `DefaultAEADOptions()` sets both tracking
flags true, a 350GB byte limit, and `NonceSize: 12`
(`pkg/types/types.go:462-506`).

**The only implementation in this repository** is
`backend.NewMemoryAEADTracker` (`pkg/backend/aead_tracker.go:29-213`):
per-keyID maps of used nonces (hex-encoded) and a byte counter, guarded by a
`sync.RWMutex` with `sync/atomic` counters. `RotateKey` calls
`tracker.ResetTracking(keyID)` before generating the replacement key
(`backend.go:328-355`), clearing nonce history and zeroing the byte counter
for that key ID.

## Configuration

No YAML/config-file surface of its own: `symmetric.Config` is a Go struct
passed to `NewBackend`, constructed by
`pkg/xkms/register_symmetric.go:init()`, which registers under
`xkms.BackendSymmetric = "symmetric"`
(`pkg/xkms/registry.go:74-76`, "Always compiled in" — and, unlike
`register_quantum.go`, this one's doc comment matches the code: there is no
build-tag claim to contradict). Its factory `newSymmetricKeyProvider`
recognizes exactly one configuration key, `"key_dir"` (string): empty or
`"memory"` selects `storage.New()` (in-memory); any other value opens
`file.New(keyDir)` (`register_symmetric.go:33-47`).

## What is absent, half-built, or misdescribed

- **Resolved (go-xkms#1201): the Encrypt/wrap nonce guard is now durable.**
  `aead.SharedAEADNonceGuard`'s own tracker is still per-process memory with a
  per-process salt, but `pkg/server`'s `initializeAEADNonceStore` attaches a
  `pkg/aeadnonce.Store` to it at startup, and `KeyNonceGuard.UseContext` (what
  `claimAEADNonceIn` calls for both `Encrypt` and the AES-GCM wrap) claims
  through that store as well as the in-memory tracker. A claim now survives a
  restart, and — when `Storage.Backend` is `qrdb` — is visible to every node
  in the cluster. See [`architecture.md`](architecture.md)'s "Persistence: a
  durable claim, not process memory alone" for the spec citations behind the
  design and why a caller-supplied nonce is still admitted rather than
  refused outright.
- **No persistent `AEADSafetyTracker`.** This is a separate, narrower gap from
  the one above: `types.AEADSafetyTracker` is the PROVIDER-level tracker each
  `symmetric.Backend` (or `quantum.QuantumBackend`) instance optionally keeps
  for itself (`CheckNonce`/`RecordNonce`, plus the unrelated byte-limit
  counters `IncrementBytes` tracks) — defense in depth for a caller that
  embeds a backend directly rather than reaching it through `XKMSService`,
  which cannot see the service-layer guard above at all. Every deployment that
  constructs a `symmetric.Backend` (or `quantum.QuantumBackend`) without
  supplying its own `types.AEADSafetyTracker` implementation loses all
  nonce-reuse history and byte counters on process restart.
  `NewMemoryAEADTracker`'s own doc comment recommends a persistent
  implementation "for production systems"; none is shipped, and
  `grep -rln AEADSafetyTracker` across the repository (excluding tests) turns
  up no second implementation. Left in place rather than removed as dead code:
  it is not dead (every symmetric/quantum backend still calls it on its own
  Encrypt/Decrypt path), and go-xkms#1201's own attack — an RPC caller
  choosing the nonce — is fully closed by the service-layer guard above
  regardless of this tracker's state.
- **`pkg/crypto/aead`'s CPU/hardware-aware `SelectOptimal` is not called by
  `GenerateSymmetricKey`.** The auto-selection logic exists and is exported,
  but key generation takes the algorithm directly from
  `attrs.SymmetricAlgorithm` — nothing in `pkg/keyprovider/symmetric` invokes
  `aead.SelectOptimal`/`SelectOptimalBackend`. A caller that wants
  CPU-optimal cipher selection must call that function itself before setting
  `attrs.SymmetricAlgorithm`.
- **CLI and generic REST key-generation only reach AES-GCM by name**; see
  [`cli.md`](cli.md) and [`api.md`](api.md) for the exact gap between what
  the backend supports (all five algorithms, four modes) and what each
  transport's help text advertises.
- **Key-derivation (`DeriveFromSymmetricKey`) is documented in full in this
  package**, but the underlying `pkg/crypto/kdf` package (HKDF, PBKDF2,
  Argon2/Argon2i/Argon2id, SP800-108 counter/feedback/double-pipeline, X9.63,
  SP800-56A) is shared, general-purpose infrastructure already covered by
  [`../key-management/`](../key-management/) (superseding
  `docs/crypto/kdf.md`); this folder does not duplicate that coverage.

## Tests

`pkg/keyprovider/symmetric` carries the package's own suite:
`backend_test.go`, `backend_tracking_test.go`, `backend_bench_test.go`,
`backend_importexport_test.go`, `aes_key_test.go`, `chacha20_key_test.go`,
`ecb_test.go`, `tagsize_test.go`, `kdf_test.go`, `kat_test.go` (known-answer
tests), `metadata_test.go`, `metadata_rollback_test.go`,
`encrypted_data_test.go`, `export_key_material_test.go`,
`import_wipe_test.go`, plus `mock_compareanddelete_test.go` and
`mock_putifabsent_test.go` for storage-backend failure injection.
`pkg/backend/aead_tracker.go` has its own `aead_tracker_test.go`; its
behavior is additionally exercised indirectly through this package's
`backend_tracking_test.go` and the quantum package's
`aead_tracking_test.go`.
