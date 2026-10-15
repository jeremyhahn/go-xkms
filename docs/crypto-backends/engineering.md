# Crypto Backends — Engineering Contract

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface

### `xkms.Backend` — `pkg/xkms/keystore.go:36`

The full method set is listed in [`architecture.md`](architecture.md). Implement
all of it; a store that cannot do something reports so through its
`Capabilities` and returns a typed error when asked anyway. `CanSeal() bool`
is the one capability that is also a method, because sealing is checked on
every seal call. `Type() types.StoreType` is likewise a method rather than a
derived value: it answers "what kind of backend is this" without unwrapping
to `KeyProvider()`, so a `TenantScopedBackend` can answer it without
discarding its tenant scope (#163). Every implementation in the tree —
`compositeBackend`, `TenantScopedBackend`, and every test fake — has one; a
new `Backend` implementation must too, with a compile-time
`var _ xkms.Backend = (*T)(nil)` check.

`BackendConfig` (`pkg/xkms/keystore.go:187`) is the construction input.
`compositeBackend` (`:238`) is the internal fan-out used by the composite
keystore; its `Type()` maps its composed key provider's `types.BackendType`
through `backendTypeToStoreType` (`pkg/xkms/keyid.go`), so it reports the
same keyword `ID()` and the Key ID parser expect regardless of the name it
was registered under.

`SignerStore() store.SignerStorer` (`pkg/signing/store`, go-xkms#724) is
built once in `New()` from the same `storage.Backend` as `CertStorage`, so
every backend gets it for free from `compositeBackend`. `TenantScopedBackend`
does not pass it through unchanged — it wraps it so signature records are
tenant-scoped too — see [`signing/architecture.md`](../signing/architecture.md).

### `types.KeyAttributes.Backend` and `.StoreType` — `pkg/types/types.go`

`Backend` is the exact registry name a key's operation ran against —
`service.backends[name]`'s key. `StoreType` is the kind of backend that is,
reported by the resolved backend's `Type()`. See
[`architecture.md`](architecture.md#model-backend-name-vs-store-type) for the
full model and the fallback that resolves attributes with no `Backend` set
(#312).

`BackendFor` and `getBackendForKID` (`pkg/xkms/service.go`) both resolve
through the unexported `resolveBackendFromAttrs`, so the two entry points —
attribute-based and Key-ID-string-based — cannot drift on which field wins.

### `types.Capabilities` — `pkg/types/types.go:1366`

Fields: `Keys`, `HardwareBacked`, `Signing`, `Decryption`, `KeyRotation`,
`SymmetricEncryption`, `Sealing`, `Import`, `Export`, `KeyAgreement`, `ECIES`,
`Attestation`, `QuantumSigning`, `KeyEncapsulation`, `SecurityLevel`.

Helpers: `HasKeys()`, `IsHardwareBacked()`, `SupportsSymmetricEncryption()`,
`SupportsImportExport()`, `SupportsKeyAgreement()`, `SupportsECIES()`,
`SupportsQuantumSigning()`, `SupportsKeyEncapsulation()`.

`SecurityLevel` values, from `pkg/types`: `0` Low (software), `1` Medium
(cloud), `2` High (PKCS#11), `3` VeryHigh (TPM2) — `pkg/types/types.go:1589`.
It is a sort key for UIs, not an authorization input. `SecurityLevel.String()`
(`:1607`) and `.Description()` (`:1623`) give the label and one-line
description; `Capabilities.GetSecurityLevel()` (`:1760`) reads it. Beyond
PKCS#11 and TPM2, the phone backend declares High
(`pkg/backend/phone/backend.go:204`) and Vault declares Medium alongside the
cloud KMS backends (`pkg/backend/vault/vault.go:175`).

### Registration

One file per backend, `pkg/xkms/register_<backend>.go`, each guarded by the
build tag in the table below. Server-side construction is
`pkg/server/backend_<backend>.go` (`initXBackend`, called from `server.go`'s
`initializeBackends`), each with a `_stub.go` sibling for builds without the
tag.

### Registering a backend from another module

A backend that lives in another Go module registers from that module's
`init()` with `xkms.RegisterExternalBackend(xkms.ExternalBackend{Type, Factory}) error`
(`pkg/xkms/registry_external.go:56`; the type is at `:29`). The SDK
re-exports it, `ExternalBackend`, `BackendTypeRegistrationError` and the three
sentinels (`sdk/go/xkms_service.go:61`).

- **Name.** `Type` must match `validation.ValidateBackendName`: a-z, 0-9 and
  `-`, at most 64 characters. The same name is the keys' `StoreType` and the
  backend segment of their Key IDs (`<type>:signing:ecdsa-p256:<name>`). The
  `KeyProvider` the factory returns must report it from `Type()`.
- **Name claim.** `types.RegisterBackendType` (`pkg/types/backend_registry.go:94`)
  publishes the name and its factory together, in one atomic step, so no
  reader sees the name valid without its factory. `IsRegisteredBackendType`
  (`:132`) is consulted by
  `xkms.BackendType.IsValid` (`pkg/xkms/registry.go:91`), `types.StoreType.IsValid`
  (`pkg/types/types.go:332`), `types.ParseStoreType` (`:349`), and Key ID
  parsing: `validateBackend`, `keyIDToBackendType` and `backendTypeToStoreType`
  (`pkg/xkms/keyid.go:260`, `:374`, `:494`). The built-in switches are
  unchanged and checked first.
- **Construction.** `GetBackendFactory`, `IsBackendSupported` and
  `SupportedBackends` read the external factory from that same registry
  (`types.RegisteredBackendFactory`), beside the compiled-in ones. `AutoInitialize` calls it with `AutoConfig.BackendConfigs[Type]`,
  plus a `key_storage` backend prefixed `<type>/` when `AutoConfig.Datastore`
  is set.
- **Timing.** As with `phone.RegisterPlatform`, registration is accepted at any
  time and lasts for the life of the process. A backend registered after
  `AutoInitialize` is constructed by the next `AutoInitialize`.
- **Concurrency.** The external registry, `backendRegistry` and `backendFactories` are
  copy-on-write maps behind `atomic.Pointer`. Lookups never lock, and
  concurrent registrations never lose an entry.
- **Refusals.** A refused registration registers nothing and returns
  `*types.BackendTypeRegistrationError`, which matches one of three sentinels:
  - `types.ErrInvalidBackendTypeName`: the name is empty or malformed;
  - `types.ErrBackendTypeRegistered`: the name is built in (including
    xkms-only names such as `pkcs8`) or already registered;
  - `xkms.ErrNilBackendFactory`: there is no factory.

  An unregistered name stays invalid everywhere. `RequireBackend` and
  `AutoInitialize` return `ErrFeatureNotCompiled` for it.

## Backend capability matrix

Read from each backend's declared `Capabilities` and its provider semantics.
`Sealing` uses the backend's native mechanism, documented in
`pkg/types/types.go:1386` as: TPM2 → PCR-bound sealing; PKCS#11 → HSM-resident
key encryption; cloud KMS → envelope encryption; PKCS#8 → HKDF + AES-GCM.

| Backend | Tag | Hardware | Export | Attest | Sealing | Notes |
|---|---|---|---|---|---|---|
| software | — | no | yes | no | via PKCS#8 mechanism | default; material under the barrier |
| symmetric | — | no | policy | no | — | AEAD key provider |
| pkcs8 | — | no | yes | no | HKDF + AES-GCM | file-backed key provider |
| quantum | — | no | policy | no | — | ML-DSA signing, ML-KEM encapsulation |
| tpm2 | — | **yes** | no when `FixedTPM` | **yes** | PCR-bound | highest `SecurityLevel` |
| pkcs11 | `pkcs11` | **yes** | token policy | token-dependent | HSM-resident KEK | slots + SO/user PINs |
| awskms | `awskms` | provider HSM | wrapped | provider | envelope | import needs wrapping params |
| gcpkms | `gcpkms` | provider HSM | wrapped | provider | envelope | |
| azurekv | `azurekv` | provider HSM | **no** | provider | envelope | supports `Import`, deliberately not `Export` |
| vault | `vault` | no | policy | no | transit | HashiCorp Vault transit engine |
| frost | `frost` | n/a | n/a | no | — | threshold signing; see `../frost-threshold/` |
| phone | — | **yes** (TEE/StrongBox) | no | yes | — | xkey-android as HSM; see `../../xkey/docs/phone-hsm/` |
| avr | — | **yes** (secure element) when the device reports that tier | no | **yes** (DICE alias certificate) | — | read-only device identity; see `../avr-device-backend/` |

Never assume a capability from this table at a call site — read
`Capabilities` from the backend, because a deployment's token or provider policy
can be stricter than the backend's ceiling.

### `Exportable`/`Sensitive` round-tripping (go-xkms#932)

`xkms.ExportKey`, `RotateKey` and `CopyKey` resolve a key's *persisted*
policy — not the caller's current request — through `findKeyAttrs`
(`pkg/xkms/servicer_helpers.go:140`) and `loadStoredKeyAttrs`
(`pkg/xkms/service.go:859`), both of which read `Backend.ListKeys` and use
whatever it reports for `types.KeyAttributes.Exportable` and `.Sensitive`
as-is. A backend whose `ListKeys` does not populate these two fields
truthfully therefore misreports every key it enumerates, independent of what
policy the key was actually created with. The table below is each backend's
source of truth for both fields, as of the fix for #932.

| Backend | `Exportable` source of truth | `Sensitive` source of truth | Citation |
|---|---|---|---|
| software / pkcs8 / symmetric | Per-key metadata record (`keyMetadata.Exportable`/`.Sensitive`), written once at creation and never widened | Same record, `keyMetadata.Sensitive` | `pkg/keyprovider/symmetric/metadata.go:47` (`newKeyMetadata`), `pkg/backend/software/software.go:1014` (`SaveKeyMetadata` for the C_UnwrapKey path) |
| pkcs11 | The token's own `CKA_EXTRACTABLE`, read per-key by `ListKeys` — never a parallel copy. A generated key pair is always `CKA_EXTRACTABLE=CK_FALSE` (`generatedKeyExtractable`), regardless of the caller's `Exportable` request; only `ImportKey`'s `buildImportKeyTemplate` honours the caller's policy, writing it straight to `CKA_EXTRACTABLE` | The token's own `CKA_SENSITIVE`, read the same way. Every private key this backend creates, generated or imported, is `CKA_SENSITIVE=CK_TRUE` | `pkg/backend/pkcs11/pkcs11.go` `ListKeys` (reads both via `readBoolAttribute`); `pkg/backend/pkcs11/signer_rsa.go:317` (`generatedKeySensitive`/`generatedKeyExtractable`); `pkg/backend/pkcs11/pkcs11_importexport.go:701` (`buildImportKeyTemplate` doc comment) |
| tpm2 | Unconditionally `false` for every key `ListKeys` enumerates. `KeyTemplateSpec.Template` sets `FixedTPM=true`/`FixedParent=true` on every generated key (TCG TPM 2.0 Library Part 2 §12.2.3.5's "may never leave this TPM/parent"), and `ExportKey` refuses every key — generated or `ImportKey`'s duplicable sealed-keyedhash objects alike — unconditionally with `ErrExportNotSupported` | Unconditionally `true`: `ExportKeyMaterial` refuses every key unconditionally too, so plaintext is never released for any key this backend manages | `pkg/tpm2/template.go:165` (`FixedTPM`/`FixedParent` in `KeyTemplateSpec.Template`); `pkg/backend/tpm2/importexport.go:255` (`ExportKey` doc comment); `pkg/backend/tpm2/backend.go` `ListKeys` |
| awskms | Unconditionally `false`. `Capabilities().Export` is `false` unconditionally, and `ExportKey`/`ExportKeyMaterial` refuse every key regardless of policy — AWS KMS never releases key material outside the service boundary | Unconditionally `true`, for the same reason | `pkg/backend/awskms/awskms.go:563` (`Capabilities`), `:1198` (`ExportKey`), `:1246` (`ExportKeyMaterial`), `ListKeys` |
| gcpkms | Unconditionally `false`. `Capabilities().Export` is `false` unconditionally; GCP KMS exposes no API to release private key material for any protection level or import method | Unconditionally `true`, for the same reason | `pkg/backend/gcpkms/gcpkms.go:246` (`Capabilities`); `pkg/backend/gcpkms/gcpkms_importexport.go:264` (`ExportKey` doc comment), `:299` (`ExportKeyMaterial`); `ListKeys` |
| azurekv | Unconditionally `false`. `Capabilities().Export` is `false` unconditionally; Azure Key Vault exposes no API to release private key material | Unconditionally `true`, for the same reason | `pkg/backend/azurekv/azurekv.go:325` (`Capabilities`); `pkg/backend/azurekv/azurekv_importexport.go:480` (`ExportKey`), `:504` (`ExportKeyMaterial`); `ListKeys` |
| vault | Per-key metadata record (`"exportable"`), written by `GenerateKey` (unconditionally `false` — H8, an asymmetric private key's public half is already available through the ordinary read-key endpoint), `GenerateSymmetricKey` and `ImportKey` (both carry the caller's `Exportable`). `ExportKeyMaterial` is genuine for a symmetric key created exportable, via Transit's own `transit/export` endpoint; `ExportKey` (the wrapped-for-a-third-party form) has no Vault-native equivalent and always refuses | Per-key metadata record (`"sensitive"`), mirroring the caller's own `Sensitive`, consulted by the service layer the same way every backend's is | `pkg/backend/vault/vault.go:192` (`GenerateKey`, H8), `ListKeys`; `pkg/backend/vault/vault_symmetric.go:99` (`GenerateSymmetricKey`); `pkg/backend/vault/vault_importexport.go:296` (`ExportKey` doc comment), `:333` (`ExportKeyMaterial`) |

Two consequences follow directly from this table:

- On tpm2, awskms, gcpkms and azurekv, `Exportable: true` at key creation is
  accepted but can never be honoured by any code path in that backend —
  `ExportKey`/`ExportKeyMaterial` refuse unconditionally regardless of the
  flag. `ListKeys` reports `Exportable: false` truthfully rather than
  echoing the request, and the refusal error is the backend's own
  capability error (`ErrExportNotSupported`/`ErrNotSupported`), not
  `ErrKeyNotExportable` — the distinction a caller needs to tell "this
  backend never does this" from "this specific key wasn't marked for it".
- On pkcs11 and vault, `Exportable` is a real per-key policy that
  round-trips and is genuinely enforced: pkcs11 via `CKA_EXTRACTABLE` on
  import (never on generate — a generated key pair is always sealed in the
  token, `generatedKeyExtractable`), vault via Transit's `exportable` flag
  on a symmetric key (never on an asymmetric one — H8).

## Invariants

- **Capabilities are declared before use.** A caller that acts without checking
  and gets an error has a bug, not bad luck.
- **`Import` and `Export` are independent.** Azure Key Vault is the standing
  counterexample.
- **A `FixedTPM` key cannot be exported at all**, whatever the request or the
  key's `exportable` attribute says. Hardware wins.
- **A compiled-out backend never degrades to software.** Through
  `AutoInitialize` it fails closed with `*FeatureNotCompiledError`; in
  `xkmsd` its `_stub.go` logs a warning and leaves the backend absent (FROST's
  stub fails start-up). See §Configuration.
- **`Close()` releases device state.** PKCS#11 sessions and TPM contexts are
  finite; leaking them exhausts the device, not memory.
- **A local Azure Key Vault URL requires an explicit opt-in.** `azurekv.Config.VaultURL`
  naming `localhost`/`127.0.0.1` fails `Validate` with `ErrLocalVaultURLNotAllowed`
  unless `backends.azurekv.allow_local_vault_url`
  (`XKMS_BACKENDS_AZUREKV_ALLOW_LOCAL_VAULT_URL`, `azurekv.AllowLocalVaultURL`) is
  `true`. Off by default: a production configuration cannot reach a fake vault
  endpoint by accident (#140). The `xkms.AutoInitialize` map-based path
  (`pkg/xkms/register_azurekv.go`) reads the same switch from its
  `BackendConfigs[xkms.BackendAzureKV]` map under the key
  `"allow_local_vault_url"`, parsed as a `bool`; a value present under that
  key that is not a `bool` fails construction with
  `xkms.ErrInvalidBackendConfigValue` rather than being silently ignored.
- **Concurrency.** The composite is concurrency-safe. Individual backends
  serialise where the device requires it; do not assume parallel throughput from
  a single token.
- **The default backend is a function of the backend names alone**, so the same
  configuration resolves to the same store on every start. The rule is
  `xkms.ResolveDefaultBackend` (`pkg/xkms/auto.go`), applied in order: the
  requested backend when it is loaded, then the software backend, then the
  alphabetically first name. It decides where keys generated without an
  explicit backend are stored, so a choice that moved between restarts would
  move them with it (#171).

  Callers reach it differently on purpose. `xkms.Initialize` fails closed when
  `DefaultBackend` names a backend that is not loaded
  (`ErrDefaultBackendNotFound`) and consults the rule only when none was
  configured. The server (`initializeKeyStore`) resolves through the rule in
  both cases so a `default_backend` naming a backend absent from the build is
  not fatal, and logs a warning naming the configured and resolved backends.

- **A listing never renames a key's algorithm.** `PKCS8Backend.ListKeys`
  reconstructs attributes from the storage identifier: an `x25519` key is
  listed with `X25519Attributes` set and `KeyAlgorithm` unset (the shape
  `GenerateKey` accepts and the software backend's key-type validation
  requires on re-import), and an algorithm the backend does not produce is
  listed with `KeyAlgorithm` unset. It used to default both to RSA-2048
  (#154).
- **Vault asymmetric keys are non-exportable** (H8: the public half is
  already available through the ordinary read-key endpoint); a **symmetric**
  key created with `Exportable: true` is genuinely exportable through
  `ExportKeyMaterial`, Transit's own `transit/export` endpoint (#932). The
  versioned ciphertext envelope is preserved across operations; Vault key
  names use an injective (one-to-one) escape to avoid name collision.
  Wrapped export (`ExportKey`) has no Vault-native equivalent and is not
  supported for any key.
- **Vault binds AAD through Transit's `associated_data`.** It was sent as
  `context`, a key-derivation input Transit ignores for the non-derived keys
  this backend creates, so AAD bound nothing. Encrypt and decrypt now send
  `associated_data` and fail closed with `vault.ErrAssociatedDataIgnored`
  when the server's response warns it ignored the parameter.
- **GCP resolves the live primary key version** at backend initialization, and
  Azure, Vault and GCP signers **pin the resolved version** at construction time
  so version rotations do not cause unexpected signing key changes mid-request.
- **AWS signers honour per-call hash and padding configuration,** including PKCS#1
  v1.5 (non-OAEP padding), because the calling code may have explicit algorithm
  requirements.
- **PKCS#11 gained CBC, CBC-pad and ECB cipher modes** and discards sessions
  whose authentication state cannot be restored after a PIN-entry failure or
  token reset.
- **Import and export capabilities are split.** A backend can implement `Import`
  independently from `Export`. Vault gained a real BYOK (Bring Your Own Key)
  import ceremony in place of simpler paste operations.
- **An `ImportToken` is an opaque handle, never key material.** The
  unwrapping private key stays inside the backend that minted it
  (`pkg/backend/backend_importexport.go`, `ImportParameters`). The software,
  symmetric and Azure Key Vault backends generate a local RSA wrapping
  keypair, seal the private half in an `importtoken.SealedRSAKey`, and return
  a random handle naming it; `UnwrapKey`/`ImportKey` resolve the handle with a
  single-use `importtoken.Store.Take` and refuse an unknown, expired or
  replayed handle with `backend.ErrKeyNotFound`
  (`pkg/backend/azurekv/azurekv_importexport.go:62`, `:199`). Azure Key Vault
  unwraps locally and imports the result as a JWK; it does not use Key
  Vault's native key-exchange-key BYOK flow.
- **The RSA-OAEP / RSA-AES-KEY-WRAP unwrap step lives in one place,
  `importtoken.Unwrap`, and every token binds the algorithm it was issued
  for.** `importtoken.Entry{Key, Algorithm}` is the `Store` value type the
  symmetric and Azure Key Vault backends use (the software backend keeps its
  own richer per-token struct, which also tracks `keySpec`, but calls
  `importtoken.Unwrap` the same way). `Unwrap` refuses a `WrappedKeyMaterial`
  whose `Algorithm` does not match the algorithm `GetImportParameters` issued
  the token for, before the wrapping key's enclave is ever opened, with a
  typed `*importtoken.AlgorithmMismatchError` wrapping
  `backend.ErrInvalidAlgorithm`. Before #1342 only the software backend
  checked this; the symmetric and Azure Key Vault backends accepted any
  algorithm the caller's `WrappedKeyMaterial` claimed.
- **`ExportBackend.ExportKeyTo(ctx, attrs, dstParams)` wraps for a
  caller-supplied destination, `ExportKey` for a wrapping key the backend
  mints and tracks for itself.** The two are not interchangeable for a
  cross-backend copy: `ExportKey`'s `ImportToken` names a wrapping key that
  exists only in the exporting backend's own state (an in-memory map, an HSM
  object, a cloud import job), so handing it to a *different* backend
  instance's `ImportKey` names nothing that backend has ever heard of.
  `ExportKeyTo` takes `ImportParameters` obtained from the destination's own
  `GetImportParameters` and wraps under those directly. The software and
  symmetric key-provider backends implement it for real — their `WrapKey` is
  a pure cryptographic operation over whatever `ImportParameters` it is
  given, touching no backend-private state, so wrapping under a
  caller-supplied destination key is exactly as sound as wrapping under the
  backend's own. PKCS#11, TPM2, AWS KMS, GCP KMS, Azure Key Vault, Vault and
  the phone backend return `backend.ErrExportToUnsupported`: their wrap
  primitives (`C_WrapKey` against an HSM-resident wrapping-key handle, TPM
  duplication, each provider's BYOK ceremony) bind to a key object the
  backend itself manages, not an arbitrary public key handed to it by a
  caller, and refuse rather than emulate a wrap that never touches the
  boundary the backend exists to preserve. `xkms.CopyKey` is the only caller:
  it resolves the destination's import parameters first, then calls the
  source's `ExportKeyTo` with them, so a copy across two distinct backend
  registrations — not merely two tenant-scoped views of the same one — only
  succeeds when the material was genuinely wrapped for the destination
  (#154, #567).
- **A backend's registry name is never derived from its `StoreType`, or the
  reverse.** `StoreType` is what `Type()` reports about the backend's kind;
  the registry name is whatever string it was registered under and may be
  anything `validation.ValidateBackendName` accepts, including a name that is
  not a store-type keyword (`token-a` beside `token-b`, two PKCS#11 tokens).
  A producer that builds `types.KeyAttributes` sets `StoreType` from the
  resolved backend's `Type()`, never from `types.ParseStoreType(backendName)`
  — the latter is only correct when the two happen to coincide, and coincided
  for every backend that existed before #312 was fixed (#312, #297, #172).
- **`types.EncryptedData.GCMNonceMode` is self-describing, not
  environment-derived.** The symmetric (`pkg/keyprovider/symmetric`), Azure
  Key Vault and TPM2 (`pkg/tpm2`) AES-GCM `Encrypt` implementations select
  their AEAD construction through `pkg/crypto/aead.NewGCMForFreshEncrypt`:
  outside `GODEBUG=fips140=only` this is the pre-existing caller-nonce
  `cipher.NewGCM` and `GCMNonceMode` stays its zero value
  (`GCMNonceModeExplicit`); under `fips140=only`, when the caller left the
  nonce to be generated at the default full tag, it substitutes
  `cipher.NewGCMWithRandomNonce` and marks the result
  `GCMNonceModeRandom`. `Decrypt` reads the mode back off the ciphertext
  (`aead.NewGCMForDecrypt`) rather than off the current process's FIPS
  posture, so a ciphertext's own recorded framing — not the environment it
  is opened in — decides how `Nonce`, `Ciphertext` and `Tag` recombine; see
  [`docs/fips/README.md`](../fips/README.md#aead-construction). A caller
  that supplies its own nonce, or asks for a truncated tag, has no
  substitute construction under `fips140=only` and fails closed with
  `aead.ErrArbitraryIVGCMUnavailable` — this applies equally to Vault
  Transit's BYOK wrap (`pkg/backend/vault/vault_importexport.go`), whose
  wire format mandates a fixed all-zero nonce. The on-disk TLV envelope
  (`pkg/keyprovider/symmetric.Marshal`/`Unmarshal`) carries the mode as an
  extra marker byte only when it is not the zero value, so every ciphertext
  written before this mode existed remains byte-identical version-1 output
  and keeps decoding unchanged.

## Error semantics

`pkg/backend/errors.go` holds the backend-layer vocabulary; the keystore
vocabulary is `pkg/xkms/errors.go`. The credential-shaped errors matter most in
practice:

| Error | Meaning |
|---|---|
| `ErrSOPinRequired` | the backend needs a security-officer PIN before this operation |
| `ErrUserPinRequired` | the backend needs a user PIN |
| `ErrPasswordRequired` | a software/PKCS#8 provider needs its password |
| `ErrUnsupportedKeyAlgorithm` | the algorithm is valid but this backend cannot do it |
| `ErrNoBackendsConfigured`, `ErrNoDefaultBackend`, `ErrDefaultBackendNotFound` | configuration |
| `ErrNilBackendFactory` | `RegisterExternalBackend` was given a nil factory |
| `types.ErrBackendTypeEmpty` | a backend type was registered under an empty name |
| `types.ErrBackendTypeRegistered` | the name is built in or already registered |
| `types.ErrBackendTypeNotCanonical` | the name is not lowercase and trimmed |

The SDK re-exports these four as `ServiceErrNilBackendFactory`,
`ServiceErrBackendTypeEmpty`, `ServiceErrBackendTypeNotCanonical` and
`ServiceErrBackendTypeRegistered`. Any other malformed name (a space or `/`
inside it, say) is refused with the `pkg/validation` backend-name error.

**Fail closed:** a missing tag, an unreachable device, an unreadable provider
credential, or an unmet PIN requirement all return an error. No backend falls
back to software.

Unseal on every backend separates sealed data that fails authentication
(`types.ErrSealedDataAuthentication`) from environment failures; the native
signals each backend maps are listed in
[`../sealing-and-barrier/engineering.md`](../sealing-and-barrier/engineering.md)
§"Sealed-data authentication". Two new backend sentinels carry the AES-GCM
refusal on the backends where it is not a provider exception:
`azurekv.ErrCiphertextRejected` and `pkcs11.ErrCiphertextRejected` (the
latter only for `CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE`
and `CKR_AEAD_DECRYPT_FAILED`; `CKR_GENERAL_ERROR`, which SoftHSM before
2.7.0 also returns for a GCM tag mismatch, is never classified, and a
`C_DecryptInit` failure is `pkcs11.ErrDecryptInit`).

**The not-found contract is exact, not "any error means absent" (#801,
#808).** It binds every backend method that resolves a key by name, not
only `GetKey`: `Get` (the raw-blob path some backends route through KMS),
`Signer`, `Decrypter`, `Encrypt`, `GetSymmetricKey`, `SymmetricEncrypter`,
and `ExportKeyMaterial` all reach the same underlying lookup `GetKey` does —
directly, through a shared helper such as `azurekv`'s `resolveKeyVersion` or
`gcpkms`'s `resolvePrimaryVersionName`, or by delegating to `GetKey` itself
— and every one of them must return an error satisfying
`errors.Is(err, backend.ErrKeyNotFound)` if, and only if, the key genuinely
does not exist: a missing object, a missing TPM handle or blob, a PKCS#11 or
cloud-KMS search that returns zero results, a Key Vault or Vault 404. Every
other failure — a login/auth failure, a transient I/O or network error,
throttling, a corrupt or partially written blob — is a distinct error that
must NOT satisfy that check. `pkg/ca`'s `getOrGenerateCAKey` (and any caller
doing get-or-create) relies on this to decide whether generating a
replacement key is safe; collapsing every failure into "not found" lets a
reachability problem silently regenerate and persist a new key over a
hardware-backed one the caller could not currently reach.

Each backend's local `ErrKeyNotFound` (where one exists — `tpm2`, `awskms`,
`gcpkms`, `azurekv`, `vault`) is an alias of `backend.ErrKeyNotFound`, not a
separate `errors.New`, so `errors.Is` recognizes it with no wrapping
required. `pkcs11`, `pkcs8` and `software` have no local sentinel and return
`backend.ErrKeyNotFound` directly. The classification each backend applies
before returning it, applied consistently across every method listed above:

| Backend | Genuine not-found signal | Everything else |
|---|---|---|
| `software` / `pkcs8` / `quantum` | `storage.ErrNotFound` from the key store | wrapped, does not match |
| `tpm2` | `storage.ErrNotFound` from `keyBackend.Get` (private or public blob), applied by `pkg/backend/tpm2.Backend.GetKey` and, since #816, by `pkg/tpm2.TPM2.GetSymmetricKey` (`SymmetricEncrypter` delegates to it) | `pkg/backend/tpm2.ErrKeyRetrievalFailed` for `GetKey`; `pkg/tpm2.ErrKeyRetrievalFailed` for `GetSymmetricKey`/`SymmetricEncrypter` |
| `pkcs11` | a zero-result PKCS#11 object search (`FindObjectHandle` returns `(0, nil)`) | the search/session error itself (e.g. `ErrSessionPoolClosed`, `ErrSessionPoolFailed`) |
| `awskms` | `*kmstypes.NotFoundException` from `DescribeKey` (`GetKey`, `GetSymmetricKey`) | `awskms.ErrKeyRetrievalFailed` |
| `gcpkms` | `storage.ErrNotFound` from the metadata store, or a `codes.NotFound` gRPC status from `GetCryptoKey`/`GetPublicKey` (`GetKey`, `Get`, `Signer`, `Decrypter`, `GetSymmetricKey`, all through `resolvePrimaryVersionName` where applicable) | `gcpkms.ErrKeyRetrievalFailed` |
| `azurekv` | an HTTP 404 `*azcore.ResponseError` from the Key Vault client's `GetKey` (`GetKey`, and `Signer`/`Decrypter` through `resolveKeyVersion`) | `azurekv.ErrKeyRetrievalFailed` |
| `vault` | `storage.ErrNotFound` from the local metadata store for the metadata-existence check every method makes (`GetKey`, `Signer`, `Decrypter`, `Encrypt`, `ExportKeyMaterial`); for `GetSymmetricKey`'s Transit read, a nil secret with no error — Vault's own convention for a path that does not exist | `vault.ErrKeyRetrievalFailed` |

`resolveKeyVersion` (`azurekv`) and `resolvePrimaryVersionName` (`gcpkms`)
are the shared choke points `Signer`, `Decrypter` and, for `gcpkms`, `Get`
and `Delete` funnel through to resolve a key's current version before an
operation; classifying the lookup once there, rather than per caller, is
what keeps every caller's not-found behavior in agreement (#808).

`getOrGenerateCAKey` (`pkg/ca/ca.go`) is the canonical caller: it generates
only when `errors.Is(err, backend.ErrKeyNotFound)`, and returns
`ca.ErrKeyRetrievalFailed` (fail closed, no generation) for anything else.

**`pkg/tpm2` is a lower layer than `pkg/backend/tpm2`, and both classify
independently (#816).** `pkg/backend/tpm2.Backend.GetKey` reads its blobs
directly and classifies there; `pkg/backend/tpm2.Backend.GetSymmetricKey`
and `.SymmetricEncrypter` instead delegate straight to
`pkg/tpm2.TPM2.GetSymmetricKey`, so the classification for the symmetric
path lives in `pkg/tpm2` itself, not in the `Backend` wrapper. Before #816
that method returned every store failure -- including a genuinely absent
key -- as a generic wrapped error, so `errors.Is(err, backend.ErrKeyNotFound)`
never matched for a missing symmetric key; `pkg/tpm2.ErrKeyRetrievalFailed`
mirrors `pkg/backend/tpm2.ErrKeyRetrievalFailed`'s role for everything that
is not a genuine absence.

**`gcpkms.Backend.ExportKey`'s body was unreachable, not merely
unclassified (#816).** GCP Cloud KMS exposes no API to release private key
material for any protection level or import method -- an HSM-protected key
never leaves the HSM, and a `SOFTWARE` key imported via
`GetImportParameters`/`ImportKey` is write-only through that import job,
with no corresponding export job. `Capabilities().Export` is therefore
`false` unconditionally, so the capability check at the top of `ExportKey`
always refuses first; a `GetCryptoKey` call and a `backend.ErrKeyNotFound`
mapping below it could never run. That dead code is deleted; `ExportKey`
now matches `awskms` and `azurekv`'s shape and returns
`backend.ErrExportNotSupported` directly, consistent with the rest of the
not-found contract never applying to a method that cannot reach a lookup.

## Configuration

### Build toggles

Every optional feature is a `WITH_*` variable in the root `Makefile`
(`Makefile:20-48`), and every one defaults to `1`: a build opts a feature
**out** with `WITH_<FEATURE>=0`. `FEATURE_TOGGLES` (`Makefile:46`) lists them
all. The provider umbrellas `WITH_AWS`, `WITH_GCP` and `WITH_AZURE`
(`Makefile:53-69`) are unset by default and, when set, override their
provider's KMS and object-storage toggles together.

Each toggle appends its build tag to `BUILD_TAGS` (`Makefile:82-125`), which
becomes `TAG_FLAGS := -tags "$(BUILD_TAGS)"` (`Makefile:129-130`). `build-cli`
builds `xkmsctl` with `CLI_TAGS` (`Makefile:142`, `BUILD_TAGS` minus `pkcs11`,
plus `gms_pure_go`). `make build-full` and `make build-minimal`
(`Makefile:478-486`) run the `build-profile` target with every toggle forced
to `1` or `0`.

The toggles that gate a backend are the ones `backendFeatures` maps
(`pkg/xkms/registry.go:226-235`):

| Backend | Toggle | Tag | Registration |
|---|---|---|---|
| `pkcs11` | `WITH_PKCS11` | `pkcs11` | `pkg/xkms/register_pkcs11.go` |
| `awskms` | `WITH_AWS_KMS` | `awskms` | `pkg/xkms/register_awskms.go` |
| `gcpkms` | `WITH_GCP_KMS` | `gcpkms` | `pkg/xkms/register_gcpkms.go` |
| `azurekv` | `WITH_AZURE_KV` | `azurekv` | `pkg/xkms/register_azurekv.go` |
| `vault` | `WITH_VAULT` | `vault` | `pkg/xkms/register_vault.go` |
| `frost` | `WITH_FROST` | `frost` | `pkg/xkms/register_frost.go` |

`tpm2` and `pkcs8` are in that map too, but their registrations
(`register_tpm2.go`, `register_pkcs8.go`) carry no build constraint, so both
backends are always compiled. The `tpm2` tag only gates the TPM 2.0 slot of
the PKCS#11 provider module (`pkg/pkcs11/module/backend_tpm2.go`) and the
SDK's re-export of the TPM2 NV-backed PIV certificate store
(`sdk/go/pivcert_backends_tpm2.go`).

The release targets build with the fixed lists `CLI_BUILD_TAGS` and
`SERVER_BUILD_TAGS` (`Makefile:74-76`, used at `Makefile:948-977`), not with
the toggles.

The remaining toggles gate no key backend. `WITH_AWS_S3`, `WITH_MINIO`,
`WITH_GCP_STORAGE`, `WITH_AZURE_BLOB`, `WITH_GLACIER` and `WITH_AZURE_ARCHIVE`
(`Makefile:31-36`) add the go-objstore tags `awss3`, `minio`, `gcpstorage`,
`azureblob`, `glacier` and `azurearchive` (`Makefile:108-125`) for the
embedded qrdb datastore's object-store and backup targets; `WITH_AWS` also
sets `WITH_AWS_S3` and `WITH_GLACIER`, `WITH_GCP` sets `WITH_GCP_STORAGE`, and
`WITH_AZURE` sets `WITH_AZURE_BLOB` and `WITH_AZURE_ARCHIVE` (`Makefile:56-69`).
The codec tags `codec_cbor codec_json codec_msgpack` are not toggles: they
seed `BUILD_TAGS` (`Makefile:82`) because the qrdb DAO layer needs them. The
toggles do not reach `TEST_TAGS` (`Makefile:408`), and a plain `go build`
outside `make` passes no tags at all. `make show-backends` (`Makefile:4701`)
prints the key-backend toggles and the resulting `BUILD_TAGS`.

`xkey/Makefile` has its own, smaller set: `WITH_PKCS11` (`xkey/Makefile:35`)
and the same six object-store toggles (`xkey/Makefile:44-49`), listed in its
`FEATURE_TOGGLES` (`xkey/Makefile:50`), the same three umbrellas over the
object-store family only (`xkey/Makefile:53-57`), and its own `build-full` /
`build-minimal` (`xkey/Makefile:237`, `:242`).

### A configured backend that is not compiled in

What happens depends on the entry point:

- **`xkms.AutoInitialize`** (SDK embedders, xkey) fails closed. A
  `BackendConfigs` key or `DefaultBackend` naming an unregistered backend
  returns `*xkms.FeatureNotCompiledError` (`pkg/xkms/auto.go:79-88`), whose
  `Feature`, `Toggle` and `Tag` fields name the backend, its `WITH_*` toggle
  and its build tag (`pkg/xkms/errors_auto.go:35-49`); it matches
  `xkms.ErrFeatureNotCompiled` with `errors.Is`. `xkms.RequireBackend`
  (`pkg/xkms/registry.go:242`) applies the same check to a direct factory
  lookup. The check covers any name with no registered factory: a
  misspelled `BackendConfigs` key, and `avr`, which `pkg/xkms` never
  registers (its `FeatureNotCompiledError` has an empty `Toggle`; the AVR
  backend is constructed directly over a caller-opened link, see
  [`../avr-device-backend/`](../avr-device-backend/)). A `DefaultBackend`
  that is not a valid `BackendType` at all is not checked and falls back
  through `ResolveDefaultBackend` (`pkg/xkms/auto.go:84`, `:217`). Tests:
  `pkg/xkms/auto_test.go` `TestAutoInitialize_*FailsClosed`.
- **`xkmsd`** builds backends in `pkg/server`. For `pkcs11`, `awskms`,
  `gcpkms`, `azurekv` and `vault`, an enabled config section in a binary
  without the tag logs a warning and the server starts without that backend
  (`pkg/server/backend_vault_stub.go:19-24` and its siblings). `frost` fails
  closed with `*server.ErrNotCompiledIn`
  (`pkg/server/backend_frost_stub.go:25-30`).

Runtime backend configuration is the `backends:` section of the server config
(`pkg/config/config.go`), described per backend in §"Per-backend
configuration" below. Provider credentials come from the server's side —
its config (as `credential://` references) or its process environment —
never from a file in this repo.

**`pkg/backend/tpm2.Config.KeyDir` has no default** (`config.go:108-118`,
issue #926): `Validate` returns `*errs.Detail` wrapping `ErrKeyDirRequired`
when both it and `Config.KeyStorage` (a pre-built `storage.Backend`,
go-xkms#1345 batch 2) are empty, rather than resolving a directory relative
to the process's working directory. `pkg/server`'s `resolveTPM2KeyDir`
(`pkg/server/backend_tpm2.go:31`) derives `KeyDir` from
`embeddednode.ResolveTPM2KeyDir` (`pkg/embeddednode/embedded_node.go`), which
derives it from `datastore.path` and itself returns
`*embeddednode.ErrDatastorePathRequired` when that is unset -- both layers
fail closed with a typed error rather than falling back to a cwd-relative
path. `pkg/xkms.AutoInitialize` instead derives `KeyStorage` from
`AutoConfig.Datastore` (`pkg/xkms/auto.go`, via `register_tpm2.go`'s
`"key_storage"` factory key) the same way it does for every other backend; a
caller that leaves `Datastore` nil and wants the tpm2 backend must set
`key_storage` explicitly in `BackendConfigs`, or the backend factory returns
an error and `AutoInitialize` skips it (logged, not fatal, matching every
other backend that fails to initialize at run time, `pkg/xkms/auto.go:117-123`).

`AutoInitialize` does **not** skip a backend whose key storage it cannot
derive: when `storage.NewPrefixBackend` over `Datastore` fails, it returns
`*xkms.BackendStorageError` (`pkg/xkms/auto.go:112-115`), which names the
backend and wraps the cause, and matches `xkms.ErrBackendStorageUnresolved`
as well as the cause with `errors.Is` (`pkg/xkms/errors_auto.go:58-72`).

### Per-backend configuration

Every backend has two configuration surfaces. The first is the `xkmsd` YAML
section `backends.<name>`: `config.BackendsConfig` (`pkg/config/config.go:1113`),
mapped onto the package `Config` by `pkg/server/backend_<name>.go`. The second
is the SDK map `AutoConfig.BackendConfigs[<name>]`, read by the factory in
`pkg/xkms/register_<name>.go`. The two do not expose the same keys. Every
package `Config` has a `Validate` that its constructor calls first.

A field typed `*types.SecretValue` (AWS `secret_key`, Azure `client_secret`,
Vault `token`, PKCS#11 `pin`) must be a `credential://<name>` reference. How
those references resolve is described in
[`../backend-credentials/`](../backend-credentials/engineering.md) and
[`../xkmsd-configuration/engineering.md`](../xkmsd-configuration/engineering.md).

**Defect: cloud backends cannot be constructed through `xkmsd` or
`AutoInitialize`.** The awskms, gcpkms, azurekv and vault `Config.Validate`
methods all require `CertStorage`:

- awskms: `pkg/backend/awskms/config.go:108`
- gcpkms: `pkg/backend/gcpkms/config.go:123`
- azurekv: `pkg/backend/azurekv/config.go:118`
- vault: `pkg/backend/vault/config.go:83`

Each `NewBackend` calls `Validate` first: `awskms.go:78`, `gcpkms.go:171`,
`azurekv.go:176`, `vault.go:75`. Neither caller sets `CertStorage`:

- the `xkmsd` initializers (`pkg/server/backend_awskms.go:43-50` and its
  gcpkms, azurekv and vault siblings);
- the SDK factories (`pkg/xkms/register_awskms.go:46`, `register_gcpkms.go:48`,
  `register_azurekv.go:53`, `register_vault.go:52`).

All four therefore fail with `cert storage is required`. The SDK factories
also set `KeyStorage: storage.New()` (in memory), so they ignore the
`key_storage` that `AutoInitialize` derives from `Datastore`.

#### software

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `path` (`pkg/config/config.go:1127`; built at `pkg/server/server.go:1065`) |
| SDK | `key_storage` |

`software.Config` needs `KeyStorage`; `Tracker` is optional
(`pkg/backend/software/config.go:38`). The backend is a facade over two
providers:

- asymmetric keys go to a PKCS#8 provider (`pkg/backend/software/software.go:162`);
- symmetric keys go to the symmetric provider (`software.go:179`).

A nil `Tracker` gets `backend.NewMemoryAEADTracker()` (`software.go:171`). That
in-memory tracker is the only implementation in the repository; see
[`../symmetric-aead/`](../symmetric-aead/engineering.md).

RSA sizes are bounded by `types.ValidateRSAKeySize` to 2048–4096 bits
(`pkg/types/algorithms.go:666-671`). The symmetric algorithms are AES-128/192/256-GCM,
ChaCha20-Poly1305 and XChaCha20-Poly1305
(`pkg/keyprovider/symmetric/encrypted_data.go:273-291`).

#### pkcs8

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `path` (`pkg/config/config.go:1133`; built at `pkg/server/server.go:1083`) |
| SDK | `key_storage`, `allow_plaintext_keys` |

- **Password protection.** When `KeyAttributes.Password` is set, the key is
  stored as an encrypted PKCS#8 blob (`pkg/keyprovider/pkcs8/pkcs8.go:277`,
  `:333`) via `github.com/youmark/pkcs8` (`:688`, `:726`).
- **Key agreement.** `DeriveSharedSecret` (`pkcs8.go:820`) supports X25519 and
  the NIST curves; `Capabilities` reports `KeyAgreement: true` and
  `SymmetricEncryption`/`ECIES: false` (`pkcs8.go:75-79`).
- **Sealing.** `Seal` derives an AES-256-GCM key from the private key with
  stdlib HKDF-SHA256 (`pkg/keyprovider/pkcs8/sealer.go:305`).
- **Close.** Every operation after `Close` returns `pkcs8.ErrStorageClosed`
  (`pkg/keyprovider/pkcs8/errors.go:32`).

#### tpm2

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `device_path`, `use_simulator`, `simulator_host`, `simulator_port`, `srk_handle` (default `0x81000001`), `platform-pcr` (default 16) and `platform-pcr-bank` (default `sha256`) from the embedded `tpm2.PlatformPCRSelection` (`pkg/tpm2/config.go:182-185`), `vtpm` (`pkg/config/config.go:1141`; mapped at `pkg/server/backend_tpm2.go:109-117`) |
| SDK | `device`, `key_storage`, `use_simulator`, `simulator_host`, `simulator_port` (`pkg/xkms/register_tpm2.go:54-66`) |

When neither a device nor the simulator is configured, `Validate`
(`pkg/backend/tpm2/config.go:105`) defaults the device to `/dev/tpmrm0`. A
missing device returns `ErrTPMNotAvailable`.
Everything about SRK, sessions, PCR policy, PIN enrollment and NV storage is in
[`../tpm2/`](../tpm2/engineering.md).

#### pkcs11

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `library`, `token` (label), `pin` (`pkg/config/config.go:1188`) |
| SDK | `library`, `config`, `pin`, `so_pin`, `label`, `slot`, `key_storage`, `cert_storage`, `key_dir` (`pkg/xkms/register_pkcs11.go:54-111`) |

`xkmsd` only logs in (`pkg/server/backend_pkcs11.go:23`). Initializing a token
with its SO PIN is an operator step. A Nitrokey HSM is detected as a
SmartCard-HSM device (`pkg/pkcs11/manager/detect.go:85-97`). Mechanisms,
session pool and PIN handling are in
[`../pkcs11-backend/`](../pkcs11-backend/engineering.md).

#### awskms

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `region`, `access_key`, `secret_key`, `endpoint`, `key_id` (`pkg/config/config.go:1202`) |
| SDK | `region`, `access_key_id`, `secret_access_key`, `session_token`, `endpoint`, `key_id` (`pkg/xkms/register_awskms.go:49-64`) |

`key_id` names an existing CMK for the barrier seal key. It accepts a key ID,
key ARN, alias name or alias ARN.

`Validate` (`pkg/backend/awskms/config.go:83`) requires a well-formed `region`.
The access-key pair must be set together or not at all.

**Credentials.** When both access keys are set, they are used as static
credentials, with `session_token` optional. Otherwise the AWS SDK default
chain is used, through `awsconfig.LoadDefaultConfig`
(`pkg/backend/awskms/awskms.go:138-153`).

**Generation.** `getKeySpec` (`awskms.go:492-513`) maps every RSA request to
`RSA_2048` and every ECDSA request to `ECC_NIST_P256`, regardless of the
requested size or curve (**defect**). Symmetric and HMAC keys use
`SYMMETRIC_DEFAULT`.

**Signing.** Supported schemes are RSASSA-PSS and PKCS#1 v1.5 with
SHA-256/384/512, and ECDSA with SHA-256/384/512 (`awskms.go:947-974`).

**Import.** The wrapping key spec is RSA-2048 (`awskms.go:1057`).

#### gcpkms

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `project_id`, `location`, `key_ring`, `credentials_file` (`pkg/config/config.go:1222`) |
| SDK | `project_id`, `location_id`, `key_ring_id`, `credentials_file`, `endpoint`, `insecure` (`pkg/xkms/register_gcpkms.go:51-66`) |

`Validate` (`pkg/backend/gcpkms/config.go:87`) checks the following:

- project, location and key ring are all required;
- `insecure` requires an `endpoint`;
- a configured `credentials_file` must exist.

**Credentials** (`pkg/backend/gcpkms/gcpkms.go:175-196`):

- `CredentialsJSON` takes precedence over `CredentialsFile`.
- With neither set, Application Default Credentials are used.
- `insecure` disables authentication and uses plaintext gRPC.

`xkmsd` cannot set `endpoint`, `insecure` or `CredentialsJSON`.

**Generation.** RSA keys are PKCS#1 SHA-256 at 2048, 3072 or 4096 bits
(`gcpkms.go:424-430`). EC keys are P-256 with SHA-256 or P-384 with SHA-384
(`gcpkms.go:518-522`). Symmetric keys use `GOOGLE_SYMMETRIC_ENCRYPTION`
(`gcpkms.go:632`).

**Import.** Import jobs use the `HSM` protection level
(`gcpkms_importexport.go:65`).

#### azurekv

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `vault_url`, `tenant_id`, `client_id`, `client_secret`, `allow_local_vault_url` (`pkg/config/config.go:1231`) |
| SDK | `vault_url`, `tenant_id`, `client_id`, `client_secret`, `allow_local_vault_url` (`pkg/xkms/register_azurekv.go:56-72`) |

`Validate` (`pkg/backend/azurekv/config.go:81`) requires a well-formed
`vault_url`. Tenant, client ID and client secret must be set together or not
at all.

**Credentials.** A complete service principal uses `ClientSecretCredential`
(`pkg/backend/azurekv/azurekv.go:248`). Otherwise `DefaultAzureCredential` is
used (`azurekv.go:304`).

**Generation** (`azurekv.go:629-658`). Keys are always software-protected
RSA-2048 or EC P-256, regardless of the requested size or curve (**defect**).
Symmetric keys are `oct` keys. Imported keys are `RSA-HSM`/`EC-HSM`
(`azurekv_importexport.go:189`, `:393`, `:398`), on P-256, P-384 or P-521
(`:450-454`).

**Signing** (`azurekv.go:664-713`):

- PS256/384/512 when the signer opts are PSS;
- otherwise RS256/384/512 by hash;
- ES256/384/512 for EC keys.

**Decryption** (`azurekv.go:1221-1263`) is RSA only:

- RSA-OAEP-256 by default;
- RSA-OAEP for OAEP with SHA-1;
- RSA1_5 when the opts are nil.

#### vault

| Surface | Keys |
|---|---|
| `xkmsd` | `enabled`, `address`, `token`, `namespace`, `mount_path` (default `transit`) (`pkg/config/config.go:1251`) |
| SDK | `address`, `token`, `transit_path`, `namespace`, `tls_ca_file`, `tls_ca_path`, `tls_cert_file`, `tls_key_file` (`pkg/xkms/register_vault.go:55-76`) |

`Validate` (`pkg/backend/vault/config.go:70`) requires `address` and `token`.
A TLS client certificate and its key must be set together.

**Authentication.** A Vault token is the only auth method; client
construction is `NewBackend` (`pkg/backend/vault/vault.go:74-120`). The TLS fields
verify the server and present a client certificate at the transport layer.
`namespace` is applied with `SetNamespace` (`pkg/backend/vault/vault.go:104`).
`xkmsd` passes no TLS options.

**Key types** (`vault.go:664-700`): rsa-2048/3072/4096, ecdsa-p256/p384/p521
and ed25519. Symmetric and BYOK keys are `aes256-gcm96`
(`vault_symmetric.go:112`, `vault_importexport.go:57`).

## Persistence

Backends persist through their own store: a device, a provider, or — for
software and PKCS#8 — files under the configured key directory, held under the
barrier. Certificate blobs go to go-objstore via
`certstore.CertificateStorageAdapter` (`Backend.CertStorage()`).

## Test strategy

- **Unit** — `pkg/backend/*_test.go` including `capabilities_test.go`,
  `backend_importexport_test.go`, `backend_symmetric_test.go`; per-backend
  suites in each backend package. `pkg/backend/mocks` provides substitutes.
- **External registration** — `pkg/xkms/extbackend` is a test-only package
  that stands in for an outside module: it registers a backend from `init()`,
  builds it through `AutoInitialize`, addresses it by Key ID, covers every
  refusal, and races registration against lookup under `-race`.
- **Integration** — one directory per backend under `test/integration/`:
  `awskms`, `gcpkms`, `azurekv`, `vault`, `pkcs11`, `pkcs8`, `tpm2`, `quantum`,
  `backend`, `signing`, `crypto`. Each is tag-gated to match its backend.
- **Hardware** — TPM2 suites run against a simulator by default
  (`simulator_host`/`simulator_port` in the config; note that the TPM simulator
  serves exactly one client at a time, so suites must not share it).
- **Fault injection** — `pkg/tpm2` ships simulator fault tests
  (`pkg/luks/tpm_simulator_fault_test.go` is the pattern).

## Observability

Backend selection and resolution are logged with the correlation ID.
`pkg/backend/aead_tracker.go` tracks AEAD invocation counts, which is what
enforces nonce-reuse limits on symmetric backends. Metrics: `pkg/metrics`.
