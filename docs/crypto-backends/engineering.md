# Crypto Backends — Engineering Contract

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-09-23

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
(cloud), `2` High (PKCS#11), `3` VeryHigh (TPM2). It is a sort key for UIs, not
an authorization input.

### Registration

One file per backend, `pkg/xkms/register_<backend>.go`, each guarded by the
build tag in the table below. Server-side construction is
`pkg/server/backend_<backend>.go` (`initXBackend`, called from `server.go`'s
`initializeBackends`), each with a `_stub.go` sibling for builds without the
tag.

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

Never assume a capability from this table at a call site — read
`Capabilities` from the backend, because a deployment's token or provider policy
can be stricter than the backend's ceiling.

## Invariants

- **Capabilities are declared before use.** A caller that acts without checking
  and gets an error has a bug, not bad luck.
- **`Import` and `Export` are independent.** Azure Key Vault is the standing
  counterexample.
- **A `FixedTPM` key cannot be exported at all**, whatever the request or the
  key's `exportable` attribute says. Hardware wins.
- **Stub builds fail loudly, not silently.** Without its tag, a backend's
  `_stub.go` reports unavailable at construction; it never degrades to software.
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
- **Vault keys are non-exportable,** and the versioned ciphertext envelope is
  preserved across operations; Vault key names use an injective (one-to-one)
  escape to avoid name collision. Wrapped export is not supported; callers
  requiring material export must use `ExportKeyMaterial` on keys stored in a
  backend that declares `Export` capability.
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

**Fail closed:** a missing tag, an unreachable device, an unreadable provider
credential, or an unmet PIN requirement all return an error. No backend falls
back to software.

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

Build tags are assembled in the `Makefile`:

```
CLI_BUILD_TAGS    := pkcs8 awskms gcpkms azurekv vault frost codec_cbor codec_json codec_msgpack gms_pure_go
SERVER_BUILD_TAGS := pkcs8 awskms gcpkms azurekv vault pkcs11 frost awss3 minio gcpstorage azureblob glacier azurearchive codec_cbor codec_json codec_msgpack
ALL_TAGS          := integration frost pkcs8 pkcs11 awskms gcpkms azurekv vault nitrokey fido2 webauthn awss3 minio gcpstorage azureblob glacier azurearchive codec_cbor codec_json codec_msgpack
```

Individual tags are toggled by `make` variables (`Makefile:78-126`), which
assemble `BUILD_TAGS` and then `TAG_FLAGS := -tags "$(BUILD_TAGS)"`.

Runtime backend configuration is the `backends:` section of the server config
(`pkg/config/config.go`). Provider credentials come from the server process's
environment, never from a file in this repo.

## Persistence

Backends persist through their own store: a device, a provider, or — for
software and PKCS#8 — files under the configured key directory, held under the
barrier. Certificate blobs go to go-objstore via
`certstore.CertificateStorageAdapter` (`Backend.CertStorage()`).

## Test strategy

- **Unit** — `pkg/backend/*_test.go` including `capabilities_test.go`,
  `backend_importexport_test.go`, `backend_symmetric_test.go`; per-backend
  suites in each backend package. `pkg/backend/mocks` provides substitutes.
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
