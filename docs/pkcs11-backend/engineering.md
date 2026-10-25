# PKCS#11 Backend — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11-backend` · Repo: `go-xkms` · Last verified: 2026-10-12

All symbols below require `-tags pkcs11` and cgo. See
[`architecture.md`](architecture.md) for the package's place in the stack.

## Configuration — two layers

| Type | Where | Purpose |
|---|---|---|
| `config.PKCS11Config` | `pkg/config/config.go:1057` | The fields exposed in `xkmsd.yaml` |
| `pkcs11.Config` | `pkg/backend/pkcs11/config.go:32` | Full library-level configuration |

`pkg/server/backend_pkcs11.go` maps the first onto the second. Anything not
in the YAML is reachable only by constructing `pkcs11.Config` directly
(library embedding, `xkey`, tests).

### Daemon YAML (`configs/xkmsd.yaml`, commented out by default)

```yaml
# backends:
#   pkcs11:
#     enabled: true
#     library: "/usr/lib/softhsm/libsofthsm2.so"
#     token: "xkms"
#     pin: "1234"
```

```go
type PKCS11Config struct {
	Enabled bool   `yaml:"enabled"`
	Library string `yaml:"library"`
	Token   string `yaml:"token"`
	Pin     *types.SecretValue `yaml:"pin"`
}
```

`Enabled: true` with an empty `Library` fails config validation
(`"PKCS11 library is required"`, `pkg/config/config.go:1538`).
`ListEnabledBackends()` reports `pkcs11`. Environment override:
`backends.pkcs11.library` resolves under `XKMS_BACKENDS_PKCS11_LIBRARY`
(the generic `XKMS_<SECTION>_<KEY>` rule — no field-specific override code,
`pkg/config/load.go:210-249`).

### PIN resolution — `*types.SecretValue`, not a plain string

`PKCS11Config.Pin` (and `pkcs11.Config.PIN`/`.SOPIN`,
`pkg/backend/pkcs11/config.go:53,58`) are `*types.SecretValue` — one of the
protected-target fields go-qrdb's `secret.ConfigProcessor` resolves
(`docs/xkmsd-configuration/engineering.md` §"secret-bearing config field"
lists `backends.pkcs11.pin` explicitly). Practically:

- The YAML value is a reference string (e.g. `credential://...`), not a
  literal PIN in plaintext — `stringToSecretValueHookFunc` decodes it into
  the field's unresolved `Raw` form (`pkg/config/load.go:259`), and
  `resolveConfigSecrets` walks the config resolving every such field before
  the backend sees it.
- `*types.SecretValue` is walked as a single leaf key by
  `registerEnvKeys`/`walkYAMLKeys` (`pkg/config/load.go:214-249`), the same
  as any other config leaf — `backends.pkcs11.pin` resolves under
  `XKMS_BACKENDS_PKCS11_PIN` by the generic rule.
- `nil` is the only way to spell "PIN not configured"; a present-but-empty
  `SecretValue` fails config resolution outright (`pkg/config/load.go:251-257`).
- The resolved plaintext lives in the `SecretValue`'s own go-enclave sealed enclave,
  never a plain Go string, until `types.SecretValueBytes(c.PIN)`
  (`pkg/backend/pkcs11/config.go:121`) extracts it for the Cryptoki call.

`config.PKCS11Config` still has **no `so-pin` field** — the daemon YAML
cannot configure the SO PIN; it is reachable only via `pkcs11.Config.SOPIN`
when embedding the package directly. `SoftHSMConfig(tokenDir)`
(`pkg/backend/pkcs11/config.go:177`) renders a `softhsm2.conf` whose tokens
live under `tokenDir`.

## `pkcs11.Config` fields (`pkg/backend/pkcs11/config.go:32`)

| Field | YAML | Required | Meaning |
|---|---|---|---|
| `CN` | `cn` | no | Identifier for logs; the daemon sets `"pkcs11-backend"`. |
| `Library` | `library` | **yes** | Path to the Cryptoki `.so`. `Validate()` stats it; missing is `ErrLibraryNotFound`. |
| `LibraryConfig` | `config` | no | Vendor config file path (e.g. SoftHSM's `softhsm2.conf`). |
| `PIN` | `pin` | for use | `*types.SecretValue`, user PIN (`CKU_USER`). Minimum 4 characters once resolved. |
| `SOPIN` | `so-pin` | PIV / init | `*types.SecretValue`, Security Officer PIN or YubiKey management key. Same custody rules as `PIN`. |
| `Slot` | `slot` | no | `*int`. Standard tokens: physical slot number. YubiKey PIV: the PIV slot (`0x9a`/`0x9c`/`0x9d`/`0x9e`). |
| `TokenLabel` | `label` | **yes** | Preferred over `Slot` — slot numbers are not stable across reboots. `Validate()` rejects an empty label. |
| `KeyStorage` | — | **yes** | `storage.Backend` for key **metadata only** — key material stays in the HSM. |
| `CertStorage` | — | **yes** | `storage.Backend` for certificate material. |
| `Tracker` | — | no | `types.AEADSafetyTracker`; defaults to `backend.NewMemoryAEADTracker()`. Production should inject a persistent one. |
| `SessionPoolSize` | `session-pool-size` | no | `<= 0` falls back to `DefaultSessionPoolSize` (8). |

`Validate()` enforces: library path set and present, token label set, PIN/SO
PIN length once resolved, both storage backends non-nil. Convenience
predicates: `IsSoftHSM()` (path contains `libsofthsm`), `IsYubiKeyPIV()`
(path contains `ykcs11`). `String()` masks both PINs.

## Storage wiring (`pkg/server/backend_pkcs11.go`)

```go
pkcs11Backend, err := pkcs11.NewBackend(&pkcs11.Config{
	CN:          "pkcs11-backend",
	Library:     s.config.Backends.PKCS11.Library,
	TokenLabel:  s.config.Backends.PKCS11.Token,
	PIN:         s.config.Backends.PKCS11.Pin,
	KeyStorage:  keyStorage,
	CertStorage: certStorage,
})
```

`keyStorage` is `pkcs11/keys`, `certStorage` is `pkcs11/certs`
(`s.createStorage(...)`). `KeyStorage` receives only JSON metadata — the
only writer is `ImportKey`, recording handle, CN, key type, algorithm, store
type, and an `imported: true` marker. `initPKCS11Backend` calls `Login()`,
not `Initialize()` — token SO-initialization is an operator action, not a
boot action; without `Login()` every operation fails with
`ErrNotInitialized`.

Certificates can additionally live inside the token: `CertStorageConfig`
(`cert_config.go`) has modes `External` (default), `Hardware`, `Hybrid`.
`External`/`Hybrid` both require `ExternalStorage`; `Hardware`/`Hybrid` both
require `EnableHardwareStorage`.

## Mechanism map

| Operation | Mechanism | Source |
|---|---|---|
| RSA key pair generation | `CKM_RSA_PKCS_KEY_PAIR_GEN` | `signer_rsa.go:357` |
| RSA PKCS#1 v1.5 sign | `CKM_RSA_PKCS` (DigestInfo prefix built in software) | `signer_rsa.go:112` |
| RSA-PSS sign | `CKM_RSA_PKCS_PSS` | `signer_rsa.go:158` |
| RSA PKCS#1 v1.5 decrypt | `CKM_RSA_PKCS` | `signer_rsa.go:193` |
| RSA-OAEP decrypt | `CKM_RSA_PKCS_OAEP` | `signer_rsa.go:243` |
| EC key pair generation | `CKM_EC_KEY_PAIR_GEN` | `signer_ecdsa.go:247` |
| ECDSA sign | `CKM_ECDSA` (raw R‖S, re-encoded to ASN.1 DER) | `signer_ecdsa.go:91` |
| Ed25519 key pair generation | `CKM_EC_EDWARDS_KEY_PAIR_GEN` (0x1055), `CKA_EC_PARAMS` = OID 1.3.101.112 | `pkcs11.go:1027` |
| Ed25519 sign | `CKM_EDDSA` (0x1057) over the full message | `pkcs11.go:1547` |
| ML-DSA / ML-KEM generation | `CKM_ML_DSA_KEY_PAIR_GEN` / `CKM_ML_KEM_KEY_PAIR_GEN` | `pkcs11.go:805` |
| AES key generation | `CKM_AES_KEY_GEN` | `pkcs11.go:1091` |
| AES-GCM encrypt/decrypt | `CKM_AES_GCM` | `pkcs11_symmetric.go:291,425` |
| ECDH key agreement | `CKM_ECDH1_DERIVE` with `CKD_NULL` | `pkcs11_ecdh.go:362` |
| Key unwrap (hybrid stage 2) | `CKM_AES_KEY_WRAP_PAD` | `pkcs11_importexport.go:483` |
| Random | `C_GenerateRandom` | `pkcs11.go:500` |

## Key generation and algorithm limits

`GenerateKey(ctx, attrs)` dispatches on `attrs.QuantumAttributes` first, then
`attrs.KeyAlgorithm`. RSA defaults key size to 2048 (`GenerateRSAWithSize`
coerces anything `< 512` to 2048). ECDSA defaults to P-256; an unrecognized
curve OID is `ErrUnsupportedKeyAlgorithm`. Ed25519 requires PKCS#11 v3.0
Edwards support (SoftHSM ≥ 2.6) and is rejected on YubiKey PIV. ML-DSA/
ML-KEM are refused unless `probeQuantumMechanisms` saw the key-pair-gen
mechanism in `C_GetMechanismList`; `Capabilities().QuantumSigning`/
`.KeyEncapsulation` mirror the same probe. AES accepts 128/192/256 bits
only. Generated key pairs are `CKA_TOKEN=true`, `CKA_PRIVATE=true`,
`CKA_SENSITIVE=true`.

## Signing, decryption, symmetric, ECDH — see the mechanism map above for the wire mechanism; behavioral notes:

- `Verify(attrs, digest, signature)` (`pkcs11.go:1540`) verifies RSA,
  ECDSA and Ed25519 **in software** from the public key read back off the
  token, and ML-DSA on the token with `C_Verify` (`verifyPublicKey`,
  `:1570-1589`). RSA-PSS and OAEP map SHA-1/224/256/384/512 to their
  `CKM_`/`CKG_MGF1_` pair (`signer_rsa.go:37-43`).
- AES-GCM: nonce fixed at 12 bytes; tag length defaults to 16 bytes,
  accepts 12–16 (`resolveGCMTagSize`); every encrypt consults
  `types.AEADSafetyTracker` (byte budget, then nonce uniqueness) before the
  operation reaches the token. `aesGCMAlgorithms` (`pkcs11_symmetric.go:891-904`)
  lists the AEAD algorithms; the cipher path also admits CBC, CBC-PAD and ECB
  (`requireCipherMechanism`, `:158-180`).
- ECDH (`DeriveKeyECDH`): rejects a cross-curve peer with `ErrCurveMismatch`;
  the KDF from `kdfParams` runs **in software** after `C_DeriveKey`
  produces the raw shared secret. The derived object is created
  non-sensitive so its value can be read (`pkcs11_ecdh.go:394-395`);
  `SupportedCurves` is at `:63-108`. Generated EC private keys carry
  `CKA_DERIVE=true` (`signer_ecdsa.go:293`), so they are usable as ECDH base
  keys on a conforming token.
- `GenerateRandom` (`pkcs11.go:631-667`) draws from `C_GenerateRandom`.
  `Get`/`Save` return `backend.ErrNotSupported` (`pkcs11.go:270-296`): key
  material stays in the token. `RotateKey` (`:627`) is
  `ErrOperationNotSupported`.
- `DeleteKey` destroys the objects and then confirms they are gone
  (`verifyKeyRemoved`, `pkcs11.go:397-455`). `ListKeys` (`:466`) pages
  `C_FindObjects` in batches with no upper bound on the count
  (`findObjectsBatchSize` loop, `:304-321`).

## Import/export ceremony

`GetImportParameters -> WrapKey (host) -> ImportKey (C_UnwrapKey, in HSM)`;
`ExportKey (C_WrapKey, in HSM)`. `GetImportParameters` finds or creates a
persistent RSA-4096 wrapping key pair labeled `go-xkms-wrapping-key`
(no expiry — the key lives in the token). Accepted algorithms:
`RSAES_OAEP_SHA_1`, `RSAES_OAEP_SHA_256`, `RSA_AES_KEY_WRAP_SHA_1`,
`RSA_AES_KEY_WRAP_SHA_256`. The hybrid unwrap path
(`importKeyHybrid`) exists because SoftHSM2 refuses `C_UnwrapKey` with
`CKM_RSA_PKCS_OAEP` for secret keys — it decrypts an ephemeral AES KEK to
host memory, re-imports it as a session object, unwraps the target with
`CKM_AES_KEY_WRAP_PAD`, and destroys the KEK. The hybrid blob is
`[4-byte length][wrapped AES key][wrapped key material]`
(`pkcs11_importexport.go:522`); the host copy of the KEK is wiped after use
(`unwrapWithEphemeralKEK`, `:579-590`). The wrapping key is
`wrappingKeyLabel`/`wrappingKeySize` (`:44-47`). An imported key that cannot
be given its `CKA_LABEL`/`CKA_ID` is destroyed and reported as
`ErrImportedKeyUnaddressable` (`:54`). `UnwrapKey` deliberately
returns `backend.ErrNotSupported` — unwrapping only happens inside the HSM
during `ImportKey`. `ExportKeyMaterial` is restricted to `CKO_SECRET_KEY`;
`GenerateSecretKey` hard-codes `CKA_EXTRACTABLE=false`, so generated AES
keys can never be exported this way.

## Security: `CKA_SENSITIVE` vs `CKA_EXTRACTABLE`

Per PKCS#11 §4.9 Table 30: `CKA_SENSITIVE=CK_TRUE` means the value is never
revealed in plaintext (`C_GetAttributeValue(CKA_VALUE)` fails; the key can
still be wrapped). `CKA_EXTRACTABLE=CK_TRUE` means the key **may be
wrapped** (`C_WrapKey` permitted — not plaintext export).
`CKA_EXTRACTABLE=CK_FALSE` means the key can never leave the token in any
form. The import template writes both explicitly rather than trusting token
defaults, because `C_UnwrapKey`'s §5.18.4 default `CKA_EXTRACTABLE` is
`CK_TRUE` and the secret-key table's `CKA_SENSITIVE` default is `CK_FALSE`
— SoftHSM2 is stricter than the spec requires, so a template relying on
defaults would pass CI and silently import a plaintext-readable key on a
conforming HSM. `attrs.Exportable=false` at import time is permanent.
`GenerateSecretKey` sets `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`
(`pkcs11.go:1395`); `generateRSAKeyPair`/`generateECDSAKeyPair` set both
explicitly too (`generatedKeySensitive`/`generatedKeyExtractable`,
`signer_rsa.go:358-359`). YubiKey PIV templates omit them because the slot
sets them (`signer_rsa.go:362-365`).

## Sealing

The backend is a `types.Sealer` (`sealer.go:29`): `CanSeal` (`:33`) is true once
initialized, `Seal` (`:74`) encrypts with AES-GCM under a token-resident key
named by `opts.KeyAttributes`, and `Unseal` (`:163`) reports a tampered
ciphertext as `types.ErrSealedDataAuthentication` only for a return code that
names the ciphertext (see the SoftHSM section below).

## Errors (representative, not exhaustive)

`ErrLibraryNotFound`, `ErrNotInitialized`, `ErrAlreadyInitialized`,
`ErrSOPINRequired`, `ErrUnsupportedKeyAlgorithm`, `ErrCurveMismatch`,
`ErrInvalidKeyAttributes`, `ErrInvalidNonceLength`, `ErrInvalidTagSize`,
`ErrInvalidTagLength`, `ErrAttestationUnsupported`,
`ErrNoDeviceAttestationKey`, `ErrDeviceCertificateNotFound`,
`ErrSessionPoolNilContext`, `ErrSessionPoolOpen` (`errors.go:84`, `:87`),
`ErrImportedKeyUnaddressable`,
`backend.ErrNotSupported`, `backend.ErrKeyNotExportable`,
`backend.ErrAsymmetricKeyExportNotAllowed`,
`backend.ErrOperationNotSupported` (`RotateKey`; `Capabilities().KeyRotation
== false`).

## SoftHSM version — 2.7.0, built from a pinned release

Every image and workflow in this repository that runs PKCS#11 tests or ships
SoftHSM — `Dockerfile.ci`, the devcontainer (and its `Dockerfile.virt-piv`),
the integration-test image `Dockerfile`, the SoftHSM sidecar
(`test/docker/softhsm`), the `test/integration/{pkcs11,pkcs11/module,
acmeadmin,storage}` images, xkey's e2e image, the published runtime images
(`Dockerfile.{server,rest,grpc,mcp,quic,cli}` and the one `release.yml`
generates), and the `ci.yml` jobs that initialize a token — builds SoftHSM
**2.7.0** with `scripts/build-softhsm.sh` instead of installing the
distribution package (2.6.1 on Debian bookworm and Ubuntu 24.04). Images
that only compile (`Dockerfile.builder`, the build stages, `release.yml`'s
binary legs) carry no SoftHSM at all: the xkms binaries `dlopen()` a PKCS#11
module at run time and link nothing from SoftHSM.

The script is the one pin: `SOFTHSM_VERSION` and the SHA-256 of the upstream
release archive
(`https://github.com/softhsm/SoftHSMv2/archive/refs/tags/2.7.0.tar.gz`), checked
before anything is extracted. It installs at Debian's paths
(`/usr/lib/softhsm/libsofthsm2.so`, `/usr/bin/softhsm2-util`,
`/etc/softhsm/softhsm2.conf`, tokens under `/var/lib/softhsm/tokens`) — the
Alpine sidecar passes `/usr/local` as its prefix, as before — so no test,
config or path changed. Builds whose context cannot reach `scripts/`
(`build/docker/devcontainer/`, `test/docker/softhsm/`) receive it as the named build
context `softhsm-pin` from their compose file. The module is stripped and
built with the file object store only, the one every token here uses.

**Why 2.7.0 is the minimum.** On an AES-GCM tag mismatch SoftHSM 2.6.1's
`C_Decrypt` returns `CKR_GENERAL_ERROR`, the code PKCS#11 reserves for an
unrecoverable token error; 2.7.0 returns `CKR_ENCRYPTED_DATA_INVALID`. This
backend reports a ciphertext refusal as sealed-data authentication only for
a code that names the ciphertext, never for `CKR_GENERAL_ERROR`, so PKCS#11
tamper is classified only on SoftHSM ≥ 2.7.0 (or a token that answers with
`CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE` or
`CKR_AEAD_DECRYPT_FAILED`). Unchanged between the two releases: RSA-OAEP is
still SHA-1 only (see `docs/password-vault/engineering.md`).

`TestSupportedSoftHSM_ReportsTamperAsSealedDataAuthentication`
(`pkg/backend/pkcs11/softhsm_tamper_test.go`, `pkcs11` tag) is the proof on
the images: it requires the token to be SoftHSM 2.7.0 or later — failing,
with the script's name, on an image that regressed to 2.6.x — and then that
a flipped ciphertext, tag or nonce, a truncated or extended ciphertext, a
mismatched or omitted AAD and a foreign key each fail `Unseal` with
`types.ErrSealedDataAuthentication` and the token's own
`CKR_ENCRYPTED_DATA_INVALID`.

`test/scripts/softhsm-pin.test.sh` (run by `make test-scripts`) fails if any
Dockerfile, compose file, workflow or script installs a `softhsm2` /
`libsofthsm2` package, if a Dockerfile that uses SoftHSM does not build it
with the script, if a workflow runs `softhsm2-util` without it, or if the
script would accept an archive that does not hash to the pin. To bump:
change `SOFTHSM_VERSION` and `SOFTHSM_SHA256` in the script (the header
says how to take the hash) and confirm the release still answers a GCM tag
mismatch with a code `ciphertextRejections` lists.

## Testing (Makefile targets, verified current)

| Target | Layer |
|---|---|
| `make integration-test-pkcs11-backend` (alias `integration-test-pkcs11`) | This backend, against SoftHSM2 in Docker (`test/integration/pkcs11`) |
| `make integration-test-pkcs11-module-all` | The provider module — a different layer, see architecture.md |
| `make integration-test-xkey-pkcs11` | xkey's FIDO2/PIV consumer tests |
| `make coverage-pkcs11` | `./test/integration/pkcs11/...` + `./pkg/backend/pkcs11/...`, requires SoftHSM |
| `make test-quantum-pkcs11` | ML-DSA/ML-KEM capability detection and key generation |
| `make test-pkcs11-tagged` | The `pkcs11`-tag-gated unit suites against SoftHSM2 |

The client suite's Docker environment
(`test/integration/pkcs11/docker-compose.yml`) sets
`PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so`,
`PKCS11_TOKEN_LABEL=test-token`, `PKCS11_PIN=1234`, and initializes the
token before running
`go test -tags='integration pkcs11 codec_cbor codec_json codec_msgpack' ./test/integration/pkcs11`.
