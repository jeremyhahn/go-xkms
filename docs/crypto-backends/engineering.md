# Crypto Backends — Engineering Contract

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-09-08

## Exported surface

### `xkms.Backend` — `pkg/xkms/keystore.go:36`

The full method set is listed in [`architecture.md`](architecture.md). Implement
all of it; a store that cannot do something reports so through its
`Capabilities` and returns a typed error when asked anyway. `CanSeal() bool`
is the one capability that is also a method, because sealing is checked on
every seal call.

`BackendConfig` (`pkg/xkms/keystore.go:187`) is the construction input.
`compositeBackend` (`:238`) is the internal fan-out used by the composite
keystore.

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
`pkg/server/backend_factory.go` plus `backend_factory_<backend>.go`, each with a
`_stub.go` sibling for builds without the tag.

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
