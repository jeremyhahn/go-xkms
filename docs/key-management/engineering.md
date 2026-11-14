# Key Management — Engineering Contract

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-10-18

This is the file an implementing agent works from. Every identifier below was
grepped in this repository.

## Exported surface

### Client contract — `sdk/go/transport`

The client surface is defined in `pkg/api/transport/client.go` and re-exported
by `sdk/go/transport/client.go` as type aliases. Two interfaces carry this
feature:

```go
type KeyService interface {
	GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error)
	ListKeys(ctx context.Context, backend string, opts ...ListOption) (*ListKeysResponse, error)
	GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error)
	DeleteKey(ctx context.Context, backend, keyID string) (*DeleteKeyResponse, error)
	ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error)
	ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error)
	RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error)
	GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error)
	CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error)
	ExportKeyMaterial(ctx context.Context, req *ExportKeyMaterialRequest) (*ExportKeyMaterialResponse, error)
	WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error)
	WrapKeyByID(ctx context.Context, req *WrapKeyByIDRequest) (*WrapKeyByIDResponse, error)
	UnwrapKeyByID(ctx context.Context, req *UnwrapKeyByIDRequest) (*UnwrapKeyByIDResponse, error)
}

type CryptoService interface {
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)
	Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)
	Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error)
	Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)
	EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error)
	DeriveKey(ctx context.Context, req *DeriveKeyRequest) (*DeriveKeyResponse, error)
	DeriveKeyECDH(ctx context.Context, req *DeriveKeyECDHRequest) (*DeriveKeyECDHResponse, error)
	AttestKey(ctx context.Context, req *AttestKeyRequest) (*AttestKeyResponse, error)
}
```

`transport.Client` composes these with `ConnectionService`, `BackendService`,
`CertService`, `SealService` and the rest; every network transport asserts
conformance at compile time (`var _ transport.Client = (*Transport)(nil)` in
`pkg/api/transport/{grpc,quic,unix,mcp}/transport.go`).

`BackendService` carries the discovery half:

```go
type BackendService interface {
	ListBackends(ctx context.Context, opts ...ListOption) (*ListBackendsResponse, error)
	GetBackend(ctx context.Context, backendID string) (*BackendInfo, error)
	Algorithms(ctx context.Context) (*AlgorithmsResponse, error)
}
```

### Server-side composite — `pkg/xkms`

`xkms.XKMSService` is the in-process composite. Backend registration lives in
`pkg/xkms/register_<backend>.go`; the key-identifier scheme is
`pkg/xkms/keyid.go` and `composite_keyid.go`. `pkg/xkms/algorithms.go` holds
the algorithm vocabulary served by `GET /api/v1/algorithms`.

### Key ID format — `pkg/xkms/keyid.go`

A key ID (`type KeyID string`, `keyid.go:45`) is
`backend:type:algo:keyname`. `ParseKeyID` (`keyid.go:124`) splits and checks
it:

- A string with no colon is shorthand for the keyname alone; otherwise it must
  have exactly four colon-separated parts. `:::my-key` is the explicit form of
  `my-key`, and `pkcs11:::my-key` names only the backend.
- `backend`, `type` and `algo` are trimmed and lowercased. Each is optional;
  only a non-empty segment is validated. The keyname is required.
- The whole ID is at most 512 characters (`maxKeyIDLength`, `keyid.go:72`), the
  keyname at most 255 (`maxKeyNameLength`, `keyid.go:75`).

| Segment | Accepted values | Where |
|---|---|---|
| backend | `software`, `pkcs11`, `tpm2`, `awskms`, `gcpkms`, `azurekv`, `vault`, `quantum`, `frost` | `validBackends`, `keyid.go:79` |
| type | `attestation`, `ca`, `encryption`, `endorsement`, `hmac`, `idevid`, `ldevid`, `secret`, `signing`, `storage`, `tls`, `tpm` | `validateKeyType`, `keyid.go:270` |
| algo | `rsa`; `ecdsa-p256`/`-p384`/`-p521` (aliases `p256`, `p-256`, `ecdsa-p-256`, …); `ed25519`, `ed448`, `x25519`, `x448`; `aes128`/`192`/`256` (`-gcm`), `chacha20`/`xchacha20` (`-poly1305`); `ml-dsa-44`/`65`/`87`, `ml-kem-512`/`768`/`1024` (dashless aliases); `hmac-sha256`/`384`/`512`; `frost-ed25519`, `frost-ristretto255`, `frost-ed448`, `frost-p256`, `frost-secp256k1` (with or without the hash suffix) | `validateAlgorithm`, `keyid.go:295` |
| keyname | `^[a-zA-Z0-9_.\-]+$`, and never `..`, `/` or `\` | `keynameRegex`, `keyid.go:92`; `validateKeyName`, `keyid.go:344` |

The algo check is grammar only: whether a FIPS deployment may use the
algorithm is left to the Go standard library (`keyid.go:288-293`).

`NewKeyID` (`keyid.go:199`) builds an ID from its four parts under the same
rules; `ValidateKeyID` (`keyid.go:254`) runs `ParseKeyID` and discards the
result. Neither checks that the key exists.

`ParseKeyIDToAttributes` (`keyid.go:557`) turns an ID into `KeyAttributes`:
the keyname becomes `CN`; a backend sets both `StoreType` and `Backend` to the
store-type keyword (`keyid.go:574-580`); RSA gets a 2048-bit default
(`keyid.go:537-538`) and ECDSA its curve. Its algorithm mapping covers only
RSA, ECDSA, Ed25519 and the symmetric AEADs, so an ID with `ed448`, `x25519`,
ML-DSA, ML-KEM, HMAC or FROST passes `ParseKeyID` but fails here with
`*ErrUnsupportedAlgorithm` (`keyid.go:448-470`).

Errors (`keyid.go:55-67`): `ErrInvalidKeyIDFormat` (wrong shape, bad type or
algo), `ErrInvalidBackendType`, `ErrInvalidKeyName`, `ErrKeyIDTooLong`, and
`ErrBackendMismatch`. Segment and keyname failures come back as
`*ErrValidation`, which unwraps to the sentinel (`pkg/xkms/errors.go:424,
438`), so `errors.Is` matches either form.

The `Backend` interface resolves IDs through `GetKeyByID`, `GetSignerByID`
and `GetDecrypterByID`, each taking `(ctx, keyID)` (`pkg/xkms/keystore.go:139,
148, 156`).

## Invariants

- **A key ID is scoped to `{tenant, backend}`.** The same string in two
  backends names two different keys; `ListKeys` always takes a backend. The
  tenant half is enforced in the service, for every transport: see *Key
  lifecycle RPCs resolve inside the caller's tenant* below.
- **Generation is not idempotent.** `GenerateKey` on an existing ID returns
  `ErrKeyAlreadyExists` rather than replacing material. Replacement is
  `RotateKey`.
- **`sensitive` is terminal.** A key created `--sensitive` can never be
  exported, by any path, for its whole lifetime. `exportable` is likewise fixed
  at creation.
- **An import chooses its exportability once.** `ImportKeyRequest.Exportable`
  (a pointer, because the default is `true` and a plain bool cannot say
  "unset") and `Sensitive` reach the stored attributes through
  `xkms.ApplyImportExportability`, which the service, the gRPC service and
  the REST handler all call. Unset keeps the write-once default: symmetric
  material exportable, asymmetric not. An explicit `false` imports
  non-extractable secret material; nothing releases it afterwards.
- **What a key is decides whether it may leave, never what a request claims.**
  `CopyKey` resolves the source key's stored attributes from the backend's
  own listing and passes those to the export; no transport's copy request
  carries an exportability field, so a caller cannot assert one. The MCP
  handler used to build the source attributes by hand, which left the flag
  false and refused every copy (#155).
- **The kid-based Simplified API resolves a key's stored attributes, never
  the attributes its kid string implies.** `xkms.ExportKey`, `RotateKey` and
  `CopyKey` (`pkg/xkms/service.go`) take a kid (`backend:type:algo:keyname`)
  and used to pass it straight through `getBackendForKID` →
  `ParseKeyIDToAttributes`, whose result can only carry the fields the kid
  format itself encodes — `Exportable` is not one of them, so it was always
  `false` regardless of what the key was created with, and `ExportKey` by kid
  refused every key (#925). All three now resolve the backend's own record
  via `loadStoredKeyAttrs` (`pkg/xkms/service.go`), which wraps the
  tenant-aware servicer's `findKeyAttrs` (`servicer_helpers.go`) and
  reports a miss as `backend.ErrKeyNotFound`. `RotateKey` by kid needs this for the same contract the bullet
  above states for `CopyKey`: regenerating with the reconstructed attrs
  silently downgraded every rotated key to `Exportable: false`. Every other
  kid-based function (`GetKey`, `Signer`, `Decrypter`, `Delete`, `Sign`,
  `Verify`, `Encrypt`, `Decrypt`, `GetSymmetricKey`, the certificate-by-kid
  group) was audited and left on the reconstructed attrs: none of those
  operations gate on a field the kid cannot encode.
- **`CopyKey` wraps for the DESTINATION's own key, never the source's.**
  `CopyKey` calls the destination's `GetImportParameters` first, then the
  source's `ExportKeyTo(ctx, attrs, dstParams)` — never plain `ExportKey`,
  whose wrapping key the EXPORTING backend mints and tracks for itself and
  names by its own import token, meaningless to any other backend instance's
  `ImportKey`. `backend.ExportBackend.ExportKeyTo` is the method every
  `ExportBackend` implements for this: the software and symmetric
  key-provider backends perform a genuine re-wrap (`WrapKey` there is a pure
  cryptographic operation over the `ImportParameters` it is given); every
  hardware- or provider-bound backend — PKCS#11, TPM2, AWS KMS, GCP KMS,
  Azure Key Vault, Vault, the phone backend — returns the typed
  `backend.ErrExportToUnsupported` instead of emulating a wrap its wrap
  primitive does not actually perform (#154, #567).
- **Wrap/unwrap by ID never materialises plaintext outside the service.**
  `WrapKeyByID` reads the KEK and the target inside the process and returns
  only ciphertext.
- **`WrapKeyByID` wraps two kinds of target** (`pkg/xkms/servicer_key.go:1067`):
  a stored exportable symmetric key (`KeyTypeSecret` with a
  `SymmetricAlgorithm`, created `Exportable`), or caller-supplied
  `TargetKeyMaterial`. Any other stored key is refused before the backend is
  asked to export (`pkg/xkms/servicer_key.go:1198`) with `*ErrWrapTarget`,
  which matches `ErrWrapTargetNotSymmetric`
  (`pkg/xkms/errors_keyops.go:55-61`): invalid-argument on gRPC and MCP, 400
  on REST. Every symmetric create path (`GenerateKey`, `ImportKey`,
  `RotateKey`), with or without a tenant and a partition, stores keys it
  accepts; the symmetric backend lists a key ID from its last four segments
  (`pkg/keyprovider/symmetric/backend.go:257`) (go-xkms#1634).
- **An unwrap under the wrong key matches `ErrUnwrapCiphertextRejected` for
  every mechanism.** The authenticated ones (AES-KW, AES-KWP, AES-GCM) return
  `*ErrUnwrapAuthenticationFailed` (`pkg/xkms/servicer_wrapkey.go:66`), which
  matches it and keeps the mechanism's cause. The unauthenticated ones
  discard the cause (go-xkms#1634).
- **`KeyAttributes.String()` never renders `Password` or `SealData`,
  regardless of `Debug`.** (`pkg/types/types.go:1223-1256`). Before the
  2026-09-28 crypto audit a `Debug`-gated "Secrets" block printed both
  verbatim; `Debug` also defaulted to `true` for TPM2 EK/IAK/IDevID/SSRK
  keys (`pkg/tpm2/config.go`, see `docs/tpm2/engineering.md`
  "Configuration"), so any future `%v` or `slog.Any` over a `KeyAttributes`
  value would have leaked them by default. `String()` has no way to know
  whether its caller is a trusted diagnostic path or an untrusted sink (an
  error message, a log line), so the block is gone unconditionally — a
  caller that genuinely needs the secret value reads `attrs.Password` or
  `attrs.SealData` directly.
- **Rotation preserves the key ID.** Callers keep referring to the same
  identifier. Versions are the service layer's, identically on every
  backend: version `n > 1` of `K` is its own backend key `K--v<n>`, and a
  version record says which is current. The service never calls a backend's
  in-place `RotateKey`. See
  [`../tpm-policies/engineering.md`](../tpm-policies/engineering.md), "Key
  versions".
- **Concurrency.** The composite is safe for concurrent use. Ordering across
  distinct keys is not promised; per-key operations serialise where the backend
  requires it (a PKCS#11 session, a TPM context).
- **Fail closed.** An unresolvable backend, an unknown algorithm, or a policy
  denial returns an error and performs no partial work.
- **Attributes name exactly one algorithm family.** A descriptor declaring two
  — an asymmetric `KeyAlgorithm` alongside a `SymmetricAlgorithm`, say — is
  refused by the software backend rather than resolved by precedence. See
  *Contradictory algorithm families are refused* below.
- **Hash `NONE` on an in-process RSA key is refused under
  `GODEBUG=fips140=only`, never crashed on.** `Sign` and `Verify` accept the
  hash name `NONE` to sign or check caller-built bytes verbatim (PKCS#11's raw
  `CKM_RSA_PKCS`). In the only mode `crypto/rsa` *panics* on `crypto.Hash(0)`
  instead of returning an error, so the service checks
  `types.CheckRawPKCS1v15` first and returns `ErrSigningFailed` /
  `ErrVerificationFailed` wrapping `types.ErrRawPKCS1v15Enforced`. A PKCS#11
  or TPM signer is not governed by it: it builds its own `DigestInfo` and
  never reaches `crypto/rsa`. Under `fips140=on` the raw form works and is
  left alone (#486; see [FIPS: hash selection](../fips/README.md#hash-selection)).

## Import validates material against its declared type

Every backend that parses caller-supplied PKCS#8 on the import path checks the
parsed key against the attributes the caller declared for it, and refuses the
pair when they disagree. In the software backend this is
`validateKeyType` (`pkg/backend/software/software.go`): RSA, ECDSA, Ed25519 and
X25519 each have an arm, public keys are refused, and a key type no arm
recognises is refused rather than admitted.

The reason is that everything downstream reasons from the declaration rather
than from the key — the storage identifier, the reported key spec, the
algorithm a later operation selects — so a key stored under a false description
poisons all of them.

**The declared EC curve is not compared against the key's own.** `ListKeys`
reconstructs attributes from the storage identifier, which carries no curve,
and reports P-256 for every ECDSA key; copy and PKCS#11 `C_UnwrapKey` both
reach the validator through attributes built that way, so comparing curves
refuses working paths rather than catching wrong ones. A P-384 key can
therefore be imported while declaring P-256. It is inert today — the curve is
not part of the identifier and `Signer` recovers it from the DER — and go-xkms#156
tracks both the caveat and the `ListKeys` fix the comparison needs.

## Contradictory algorithm families are refused

`SoftwareBackend` is the only backend that **routes** on a key's algorithm
family: `DeleteKey`, `RotateKey`, `ImportKey`, `ExportKey` and
`ExportKeyMaterial` each choose a sub-backend by asking `attrs.IsSymmetric()`
(or inspecting `QuantumAttributes`), and its PKCS#8, symmetric and quantum
sub-backends share one flat storage namespace (`keys/{id}.key`, no per-store
prefix). Every other backend uses `IsSymmetric` only as a fail-closed guard on
a symmetric-only method, never as a fan-out.

That routing reads a different field from the one that decides the key's
identity. `IsSymmetric` consults `SymmetricAlgorithm` alone, while
`KeyAttributes.ID` resolves `X25519Attributes`, then `QuantumAttributes`, then
`KeyAlgorithm`, then `SymmetricAlgorithm`. `KeyAttributes.Validate` walks the
same precedence as `ID` and stops at the first family it finds, so it does not
object. Attributes naming two families were therefore **processed as one kind
of key and addressed as another**.

`requireSingleAlgorithmFamily` (`pkg/backend/software/family_gate.go`) refuses
them at all five sites, returning `ErrContradictoryAlgorithmFamilies`, which
also satisfies `errors.Is` for `backend.ErrInvalidAttributes`.

The two destructive cases, measured before the gate existed and pinned by
`family_gate_regression_test.go`: attributes carrying `KeyAlgorithm=RSA` with
valid `RSAAttributes` **and** `SymmetricAlgorithm=aes256-gcm` routed to the
symmetric backend, which deleted — or through `RotateKey` overwrote — the RSA
private key at the identifier `ID()` built from `KeyAlgorithm`. Both reported
success. The two export paths already failed closed, but only incidentally:
the symmetric store rejected the stored PKCS#8 DER on its AES key-size check.

**Zero families is permitted.** The gate refuses only the plural case.
Attributes naming no family resolve to the `unknown` identifier, which
addresses no key any producer writes, and refusing them breaks callers that
legitimately describe a key by little more than its common name.

**The display path resolves the family in the same order.** The `algorithm`
field the REST, MCP and gRPC key listings report comes from
`KeyAttributes.AlgorithmString` (`pkg/types/types.go`, directly below `ID`),
which walks `ID`'s switch arm for arm — `X25519Attributes`, then
`QuantumAttributes`, then `KeyAlgorithm`, then `SymmetricAlgorithm` — and
returns the display spelling (`RSA`, `Ed25519`, `ML-DSA-87`) or the empty
string when no family is set. Each transport used to carry its own
`getAlgorithmString` that gave `SymmetricAlgorithm` precedence, a third
resolution order (#336). `TestKeyAttributes_AlgorithmString_AgreesWithID`
feeds two-family literals through both methods and asserts they name the same
family, so a change to `ID`'s order that is not mirrored fails there.

The same method answers the `KeyType` field of an `ExportKeyMaterial` response
in the xkey PKCS#11 embedded transport (`xkey/pkg/pkcs11/service.go`), which
held the last surviving copy of the formatter — one with an `unknown` default
and a `KeyTypeSecret` gate that the daemon-side producer of the same field
(`pkg/xkms/servicer_key.go`) never had (#402). It is deleted rather than kept
as a documented PKCS#11-edge exception, because it is not one: no consumer at
that edge reads the field, and a backend releases raw key material only for a
single-family symmetric key, so both of the copy's extra branches were
unreachable there. **There is no fourth formatter.**

## RSA modulus size floor is enforced project-wide (go-xkms#1204)

`types.RSAKeySize2048` (`pkg/types/algorithms.go`) is the minimum RSA modulus
this project generates or imports anywhere, and `types.ValidateRSAKeySize`
(`pkg/types/algorithms.go:641`) is the one function that judges a size
against it, returning the typed `*types.RSAKeySizeError`
(`pkg/types/algorithms.go:629`) rather than an `fmt.Errorf`. It performs no
substitution: a zero size is refused exactly like any other undersized
value, so a call site that wants zero to mean "use the default" resolves
that itself before calling it.

Before go-xkms#1204, `KeyAttributes.Validate` (`pkg/types/types.go:1271`)
already enforced the floor for anything that called it, but the RPC service
layer never did: `buildKeyAttributes` and the shared import-template
resolver both built a `*types.KeyAttributes` and handed it straight to a
backend. PKCS#11's `GenerateRSAWithSize` only raised sizes below 512, and
TPM's `CreateRSA` applied no floor at all, so a `GenerateKeyRequest` or
`ImportKeyRequest` naming 1024 bits reached hardware key generation
unchecked on both backends. The fix is layered, not single-point, because
the RPC service is not the only caller of any of these:

- **Service boundary.** `pkg/xkms/servicer_key.go`'s `validateKeyAttributes`
  (line 1290) wraps `KeyAttributes.Validate` in the service's own
  `ErrValidation{Sentinel: ErrInvalidKeyAttributes}` so every transport maps
  the refusal onto the same 400-class response every other validation
  failure gets. `buildKeyAttributes` (GenerateKey, line 1430) and
  `applyKeyTemplate` (the template resolver shared by `ImportKey`,
  `GetImportParameters` and `UnwrapKeyByID`, line 1412) both call it as the
  last step before returning attributes.
- **PKCS#11.** `Backend.GenerateRSAWithSize`
  (`pkg/backend/pkcs11/pkcs11.go:1161`) resolves a zero size to
  `types.RSAKeySize2048` and then calls `types.ValidateRSAKeySize` before
  touching `b.pool`, so the refusal is reachable — and unit-testable —
  without a live HSM session. A size between 1 and 511 bits used to be
  silently promoted to 2048; it is now refused like any other undersized
  request, matching this project's "refuse, never silently substitute"
  convention elsewhere in the same file.
- **TPM.** `TPM2.CreateRSA` (`pkg/tpm2/rsa.go:71`) validates the resolved
  `spec.KeyBits` immediately after applying the `DefaultRSAKeyBits` default
  and before calling `KeyTemplate`. This is a different question from
  `rsaTemplate`'s own `definedRSAKeyBits` check (`pkg/tpm2/template.go`),
  which asks whether TPM 2.0 defines a modulus size at all — and still
  includes 1024, since TCG's reference implementation does. `ValidateRSAKeySize`
  is this project's minimum-strength policy, not a device-capability
  question, so it runs first and independently.
- **Composite Backend.** `compositeBackend.GenerateRSA`
  (`pkg/xkms/composite_keys.go:34`) is the one `xkms.Backend` implementation
  every caller in this module reaches before a concrete backend ever sees a
  request, and the CA and PIV key-generation helpers (`pkg/ca/ca.go`,
  `pkg/xkms/piv_keygen_backend.go`) reach it the same way. It refuses an
  explicitly-requested undersized modulus and leaves `RSAAttributes == nil`
  or `KeySize == 0` alone, since resolving that to the default is the
  concrete backend's job, not this layer's.

**go-xkms#1214 closed the transport-level half of this gap.**
`pkg/api/rest/handlers.go`'s `GenerateKeyHandler` and `pkg/api/grpc/service.go`'s
`GenerateKey` no longer build their own `types.KeyAttributes`: both now call
`XKMSService.GenerateKey` directly, so `buildKeyAttributes`'s
`validateKeyAttributes` step is the only place either transport's generate
path can reach a backend from. `ImportKeyHandler`, `GetImportParametersHandler`
(REST) and `ImportKey`, `GetImportParameters` (gRPC) still build their own
`types.KeyAttributes` — see "Import and GetImportParameters stay
transport-level" below for why — but each now calls
`types.KeyAttributes.Validate()` directly on the attributes it built, before
calling the backend, closing the specific gap this section used to document:
an RSA-1024 `ImportKeyRequest` or `GetImportParametersRequest` is refused
with 400 / `InvalidArgument` on every transport, the same as `GenerateKey`.
REST's `CopyKeyHandler` (`pkg/api/rest/handlers.go`) gained the same call for
its destination attributes, since it builds them from caller-supplied
`key_type`/`key_size`/`curve` fields exactly as `ImportKeyHandler` does.

## Import/export capability resolution is split by direction (go-xkms#1216)

go-xkms#1214 left `ImportKeyHandler`/`GetImportParametersHandler` (REST) and
`ImportKey`/`GetImportParameters` (gRPC) as independent, transport-local
implementations, because the service's own capability resolution
(`importExportFor`) required a backend to satisfy the *union* of
`backend.ImportBackend` and `backend.ExportBackend`
(`backend.ImportExportBackend`) even for an operation that only needed one
half. Routing those four handlers through the service as it stood then would
have silently refused an AWS-KMS-shaped import-only backend. go-xkms#1216
closes that gap at its root: the service now resolves each direction
independently, so every transport can be a thin adapter over it without
narrowing which backends it reaches.

`pkg/xkms/backend_importexport.go` declares two capability interfaces and two
resolvers instead of one union type and one resolver:

- `keyImporter` (line 35) is `backend.ImportBackend`'s four-method surface
  without its embedded `types.KeyProvider`; `keyExporter` (line 56) is
  `backend.ExportBackend`'s three-method mirror. Each exists apart from its
  `backend.*Backend` counterpart for the same reason the old `ImportExporter`
  union did: `TenantScopedBackend` cannot satisfy `backend.ImportBackend` or
  `backend.ExportBackend` structurally (`Backend.RotateKey` and
  `types.KeyProvider.RotateKey` share a name with different signatures, and
  `GenerateRSA`/`GenerateECDSA`/`GenerateEd25519` have no
  `KeyProvider.GenerateKey` equivalent at all), so it needs a narrower
  interface it *can* implement to offer the capability itself rather than
  through `KeyProvider()`, which would discard the tenant scope it stamps
  (go-xkms#163).
- `importBackendFor` (line 100) and `exportBackendFor` (line 116) each
  resolve one direction: a `*TenantScopedBackend` recurses on its base and
  answers only when the base supports that direction, stamping the tenant on
  every attribute set exactly as its other key operations do; every other
  `Backend` resolves through `b.KeyProvider().(backend.ImportBackend)` /
  `.(backend.ExportBackend)` directly, exactly as the old union resolver did
  for the half it asked for.

Every call site that used to resolve the union now resolves only the
direction it uses, so a backend implementing only one half is reachable for
that half regardless of the other:

- `pkg/xkms/servicer_key.go`: `ImportKey` (`importBackendFor`, line 288),
  `ExportKey` (`exportBackendFor`, line 361), `GetImportParameters`
  (`importBackendFor`, line 461), `ExportKeyMaterial` (`exportBackendFor`,
  line 661), `WrapKey` (`importBackendFor`, line 740) and `UnwrapKey`
  (`importBackendFor`, line 805) — `WrapKey`/`UnwrapKey` resolve import
  because both are half of the import ceremony (wrapping material for
  `ImportKey`, and reversing a wrap `WrapKey` produced), never the export
  one. `CopyKey` resolves the source as `exportBackendFor` (for
  `ExportKeyTo`) and the destination as `importBackendFor` (for
  `GetImportParameters`/`ImportKey`) — two different backends, two different
  directions. `WrapKeyByID`/`UnwrapKeyByID`'s target-backend resolution
  (`wrapTargetKeyMaterial`'s `exportBackendFor`, `UnwrapKeyByID`'s
  `importBackendFor`) and the shared `importKeyMaterial` helper (now typed
  `keyImporter`, not the deleted `ImportExporter`) follow the same rule.
- `pkg/xkms/service.go` (the package-level "embedded" API): `GetImportParameters`,
  `WrapKey`, `UnwrapKey` and `ImportKey` resolve `importBackendFor`; `ExportKey`
  resolves `exportBackendFor`; `CopyKey` resolves the source as
  `exportBackendFor` and the destination as `importBackendFor`, mirroring the
  servicer.
- `pkg/xkms/backend_tenant.go`'s `TenantScopedBackend` now has two accessors,
  `importer()` (line 248) and `exporter()` (line 262), instead of one
  `importExporter()`: `GetImportParameters`/`WrapKey`/`UnwrapKey`/`ImportKey`
  call `importer()`, `ExportKey`/`ExportKeyTo`/`ExportKeyMaterial` call
  `exporter()`. A tenant-scoped view of an import-only base now offers the
  import half and refuses the export half with the typed
  `ErrImportExportNotSupported` — and the reverse for an export-only base —
  rather than refusing both because the base cannot satisfy the union.
- `pkg/xkms/piv_keygen_backend.go`'s `ImportPIVKey` (line 224) resolves
  `importBackendFor` — PIV key installation never exports, so it only ever
  needed the import half, and the pre-fix union check blocked it on a
  backend that could never have had an export half to offer.

The `ImportExporter` union type is deleted: nothing in the codebase needs
both halves through one value, since every real ceremony (`CopyKey` included)
resolves each backend it touches for exactly one direction.

REST, gRPC and MCP were converted to thin adapters over the service for the
ceremony's request-building and capability-resolution logic, the same
conversion `GenerateKey` received in go-xkms#1214:

- REST's `GetImportParametersHandler` (`pkg/api/rest/handlers.go:1269`),
  `WrapKeyHandler` (`:1352`), `UnwrapKeyHandler` (`:1428`) and
  `ImportKeyHandler` (`:1502`) now call `h.xkmsService.{GetImportParameters,
  WrapKey, UnwrapKey, ImportKey}` directly, after the same per-transport
  400-class validation (required fields, backend-name format, key-ID format)
  every other converted handler keeps ahead of the service call. The old
  `resolveImportBackend` helper and the local `types.KeyAttributes`-building
  switch are gone.
- gRPC's `GetImportParameters` (`pkg/api/grpc/service.go:1105`), `WrapKey`
  (`:1180`), `UnwrapKey` (`:1246`) and `ImportKey` (`:1304`) do the same,
  after an explicit backend-existence probe
  (`s.lookupBackend`/`status.Errorf(codes.NotFound, ...)`) that preserves the
  RPC's existing "NotFound before any ceremony-specific validation" contract
  for a name that does not resolve. The old `importBackend` helper and the
  hand-rolled key-type switches (which had drifted from the service's own:
  gRPC's `ImportKey` used to refuse `key_size: 0` for a symmetric import,
  while the service's `unwrapSymmetricAlgorithms` table has always defaulted
  it to AES-256-GCM, matching REST, MCP and embedded) are gone.
- MCP's `handleGetImportParameters` and `handleImportKeyMaterial` already
  called the service before this change; `handleWrapKey` and `handleUnwrapKey`
  now do too, in place of the deleted `importBackend` helper.

Converting `WrapKey`/`UnwrapKey` was conditional on the service's request
types actually carrying every field those two ceremonies need — the
"service drops fields" comment that justified leaving them transport-local
was checked against the current code rather than assumed: `transport.WrapKeyRequest`/
`WrapKeyResponse` and `UnwrapKeyRequest`/`UnwrapKeyResponse`
(`pkg/api/transport/types.go`) already carry `KeySpec`, `Metadata`,
`ImportToken` and `WrappingPublicKey` on both sides, so the comment was
stale by the time this issue was filed and no transport request field had to
be added to convert them. Wire shapes are unchanged: every REST/gRPC/MCP
request and response field name, type and encoding is exactly what it was
before this conversion, including MCP's PEM-vs-DER encoding of the wrapping
key and REST's `wrapped_key`/`wrapping_public_key_pem` naming (see
[api.md](api.md)).

A backend-layer capability or policy sentinel (`backend.ErrKeyNotExportable`,
`backend.ErrImportNotSupported`, `backend.ErrExportNotSupported`,
`backend.ErrAsymmetricKeyExportNotAllowed`) can now reach a transport's error
mapper wrapped in the service's own `xkms.ErrOperationWrap`, rather than only
ever arriving as a bare error from a direct backend call. Each transport's
`mapKeyOpError` was extended to classify it either way:
`pkg/api/grpc/errors_keyops.go` and `pkg/api/mcp/errors_keyops.go` consult
`apierrors.ImportExportSentinelClasses` as a fallback tier (the same table
`mapImportExportError` already used for `ExportKey`/`CopyKey`, which still
call backend methods directly); REST's `pkg/api/rest/errors_keyops.go` adds
the same four sentinels to its own `keyOpSentinelStatus` table, matching
`mapErrorToStatusCode`'s existing classification for the handlers that still
call the backend directly. `errors.Is`/`apierrors.ClassOf` see through
`ErrOperationWrap`'s wrapping either way, so the classification — and the
wire status code — is unchanged by which path a given error took.

## Key lifecycle RPCs resolve inside the caller's tenant (go-xkms#1218)

REST's and gRPC's `GetKey`, `ListKeys`, `DeleteKey`, `RotateKey`,
`ExportKey` and `CopyKey` are thin adapters over the `XKMSService` method of
the same name (REST `pkg/api/rest/handlers.go:327`–`:1660`, gRPC
`pkg/api/grpc/service.go:430`–`:1675`). Before, they resolved the key over
the unscoped backend themselves. On REST any tenant could read, list,
delete, rotate, export and copy any other tenant's key; on gRPC it could
read and list them, and a copy landed with no tenant.

Where the tenant comes from:

- `RotateKey`, `ExportKey` and `CopyKey` take `TenantID` in their request
  struct. The transports fill it from the authenticated identity
  (`callerTenantID`), never from the wire.
- `GetKey`, `DeleteKey` and `ListKeys` take no request struct; the service
  reads the tenant from the identity on `ctx` with
  `scopedTenantIDFromContext` (`pkg/xkms/servicer_password.go:93`) at
  `pkg/xkms/servicer_key.go:162`, `:271` and `:302`. The `KeyServicer`
  signatures are unchanged, so MCP's `getKey` and the embedded transport are
  scoped by the same change.

Both routes end at `tenantScopes` (`pkg/xkms/servicer_helpers.go:65`): a real
tenant gets a `TenantScopedBackend`, whose `ListKeys`
(`pkg/xkms/backend_tenant.go:94`) returns only that tenant's keys, and the
system tenant or no identity gets the unscoped backend. The lookup by common
name is `findKeyAttrs` (`pkg/xkms/servicer_helpers.go:140`) over that view,
so another tenant's key is the same bare `ErrKeyNotFound` a missing key is.
The refusal equals a genuine miss because nothing takes a different path for
it, not because an error is rewritten. The transports map it with
`mapKeyOpError` (`pkg/api/rest/errors_keyops.go:66`,
`pkg/api/grpc/errors_keyops.go:96`) to 404 / `NotFound`.

`ListKeys` paginates before it reads any public key: it collects the scoped
backend with each key, applies the page, then fills `PublicKeyPEM` for that
page only (`publicKeyPEMOf`, `pkg/xkms/servicer_key.go:244`). The transports
hand their decoded pagination to the service with
`transport.WithPageRequest` (`pkg/api/transport/pagination.go:93`).
`keyInfoFromAttrs` (`pkg/xkms/servicer_key.go:1673`) renders algorithm, RSA
size, curve and partition, so gRPC's `KeyInfo` keeps every field it had.

`ExportKey` and `CopyKey` still resolve import/export through the union
`importExportFor`; see the section above. A backend missing it is refused
by `unsupportedHalf` (`pkg/xkms/servicer_key.go:1661`), which matches both
`ErrOperationNotSupported` and the precise `backend.ErrExportNotSupported` /
`backend.ErrImportNotSupported`, so the refusal says which half was
missing. An import-only backend is therefore not a `CopyKey` destination on
any transport until the capability split lands. REST's and gRPC's own
copies asserted only `backend.ImportBackend` for the destination, but they
wrapped under the source's token (plain `ExportKey`), so a copy between two
backend instances never succeeded on them anyway.

`mapKeyOpError` gained two classifications for causes the service wraps
rather than replaces. `xkms.ErrBackendNameValidation` is 400 /
`InvalidArgument`. REST falls back to `mapErrorToStatusCode`, so a wrapped
`backend.ErrKeyNotExportable` stays 403 and a wrapped
`storage.ErrAlreadyExists` 409. gRPC falls back to
`apierrors.ImportExportSentinelClasses`, as `mapImportExportError` does.

Tests: `pkg/api/rest/handlers_keyops_crosstenant_test.go` and
`pkg/api/grpc/service_keyops_crosstenant_test.go` drive each RPC as tenant A
against tenant B's key and compare the answer, byte for byte, with the one
for the same key ID in a deployment where no tenant holds it. They also
assert tenant B's key survives, and that a tenant's copy lands in its own
tenant. `pkg/xkms/servicer_key_tenant_lifecycle_test.go` pins the service
side.

## Key agreement (ECDH)

A backend that supports ECDH implements `types.KeyAgreement`
(`pkg/types/types.go:2814`):

```go
DeriveSharedSecret(ctx context.Context, attrs *KeyAttributes, publicKey crypto.PublicKey) ([]byte, error)
```

`attrs` names the local private key; `publicKey` is the peer's. Callers check
`Capabilities().KeyAgreement` (`pkg/types/types.go:1678`) before using it. The
software backend delegates to the PKCS#8 key provider
(`pkg/backend/software/software.go:1221-1222`), which supports X25519 and the
NIST curves — see
[crypto-backends engineering](../crypto-backends/engineering.md#pkcs8).

The raw shared secret is not a key. Derive keys from it with a KDF:

- `pkg/crypto/x25519` — `KeyAgreement.DeriveKey(sharedSecret, salt, info, keyLength)`
  (`pkg/crypto/x25519/x25519.go:63`) is HKDF-SHA256 through the stdlib
  `crypto/hkdf`, so a FIPS 140-only refusal is returned as an error rather
  than a panic; it rejects an empty secret, a non-positive length and lengths
  above 8160 bytes (`x25519.go:125-147`).
- `pkg/crypto/ecdh` — `DeriveSharedSecret(*ecdsa.PrivateKey, *ecdsa.PublicKey)`
  (`pkg/crypto/ecdh/ecdh.go:56`) for NIST-curve keys held in process.
- The KDF a backend applies is selected by `types.KDFParams`; see
  [Key Derivation Functions](../crypto/kdf.md).

A runnable X25519 example — generation, agreement, HKDF derivation — is in
`examples/advanced/x25519-ecdh/main.go`.

## Per-board OTA image keys

go-xkms holds one ES256 key per trusted-firmware board, which signs that
board's OTA images. The service is `pkg/xkms/ota_image_keys.go`. Every
transport reaches it through the four `transport.Client` methods
`CreateOTAImageKey`, `RotateOTAImageKey`, `SignOTAImage` and
`ExportOTAImageKey` (`pkg/api/transport/client.go:71`, `:75`, `:79`, `:84`).
The calls on each transport are in [api.md](api.md#per-board-ota-image-keys),
and the xkmsctl verbs are in
[cli.md](cli.md#key-ota-image-create--rotate--sign--export).

**Board id and key ID.** `OTAImageKeyID(boardID)` returns the board's key
ID, `ota-image-<board-id>` (`ota_image_keys.go:36`, `:48-54`). A board id
is 1-63 characters (`:39`) matching `^[a-z0-9]+(-[a-z0-9]+)*$` (`:44`):
lowercase alphanumeric words joined by single hyphens. A doubled hyphen is
refused, so a board key ID can never take the shape of a key version's
backend name, `K--v2` (`:40-43`). Any other id returns `ErrInvalidBoardID`
(`:50`).

**ES256 only.** `OTAImageAlgorithmES256` is `"ES256"`: ECDSA on P-256 with
SHA-256, per RFC 7518 §3.4 (`ota_image_keys.go:33`). The request's
`Algorithm` may be empty, which selects ES256, or `"ES256"`. Anything else
returns `ErrOTAImageAlgorithm` (`:56-61`).

- `CreateOTAImageKey` generates a `signing` key, `ecdsa` on `P-256`, under
  the board's key ID (`:68-81`).
- Before a rotate, a sign or an export, `requireES256Key` checks that the
  current version is an ECDSA P-256 key (`:195-214`). A key created under
  the board's key ID by another path is therefore never rotated, used or
  exported as an OTA image key (`:213`, `ota_image_keys_test.go:174`,
  `ota_image_keys_export_test.go:130`).

**One key per board.** A second create for the same board returns
`ErrKeyAlreadyExists`. That holds after a rotate too
(`ota_image_keys.go:73`, `ota_image_keys_test.go:86`).

**Rotate.** `RotateOTAImageKey` creates the key's next version through
`RotateKey` and makes it current (`ota_image_keys.go:85-98`). The response
carries the new `KeyVersion` and `CertificateReissueRequired`
(`pkg/api/transport/types.go:685`, `:698`). Earlier versions stay, and an
image signed with one still verifies:
`TestRotateOTAImageKey_OldVersionStillVerifies`
(`ota_image_keys_test.go:123`) signs under version 1, rotates, signs under
version 2, and both signatures verify against their own version.

**Sign.** `SignOTAImage` signs with the current version. The hash is
SHA-256, and with `DataIsDigest` the data is already the image's SHA-256
digest (`ota_image_keys.go:116-123`). The response's `KeyVersion` names the
version that signed. The signature is the OTA_AUTH encoding of ruling 136:
RFC 9053 §2.1 fixed-width `r || s`
([rfc-9053.txt](../references/rfc-9053.txt)), each integer big-endian and
left-padded with zeros to the curve's byte width, so 64 bytes for ES256. The
trusted-firmware 328P and 32U4 boards carry no DER parser. `SignOTAImage`
converts the backend's ASN.1 DER signature (`:127`,
`fixedWidthECDSASignature` at `:221`). Every other signature the service
returns, the generic `Sign` on the same key included, stays DER.

**Export.** `ExportOTAImageKey` returns the public half of the current
version of the board's key, never its private key (`ota_image_keys.go:139-160`).
It reads the public key from the backend's signer, so it works on a
non-extractable key too (`:204-206`). It is a read of a public key, so every
transport checks `keys:get`, not `keys:export`, which stays reserved for
private material. The response is `ExportOTAImageKeyResponse`
(`pkg/api/transport/types.go:668-682`):

| Field | JSON | Value |
|---|---|---|
| `BoardID` | `board_id` | the request's board id |
| `KeyID` | `key_id` | `ota-image-<board-id>`, the record that binds the key ID to the board |
| `KeyVersion` | `key_version` | the exported version, always the current one |
| `Algorithm` | `algorithm` | `ES256` |
| `PublicKey` | `public_key` | raw `X \|\| Y`, 64 bytes |
| `COSEKey` | `cose_key` | the COSE_Key, deterministic CBOR |

`otaImagePublicKeyEncodings` produces the two encodings
(`ota_image_keys.go:162-189`):

- `PublicKey` is the uncompressed P-256 point without its `0x04` prefix:
  `X` then `Y`, each 32 bytes big-endian with its leading zero octets kept
  (RFC 9053 §7.1.1). `TestOTAImagePublicKeyEncodings_LeftPadsCoordinates`
  (`ota_image_keys_export_test.go:155`) pins a key whose coordinate starts
  with a zero octet.
- `COSEKey` is a COSE_Key, RFC 9052 §7 ([rfc-9052.txt](../references/rfc-9052.txt)),
  with the EC2 parameters of RFC 9053 §7.1.1. go-cose builds it
  (`cose.NewKeyEC2`, `:179`) and encodes it in RFC 8949 §4.2.1 core
  deterministic CBOR ([rfc-8949.txt](../references/rfc-8949.txt)): definite
  lengths and the map keys in bytewise order. The map is:

| Label | Parameter | Value |
|---|---|---|
| 1 | `kty` | 2 (EC2) |
| 2 | `kid` | the key ID as a byte string, `ota-image-<board-id>` (`:183`) |
| 3 | `alg` | -7 (ES256) |
| -1 | `crv` | 1 (P-256) |
| -2 | `x` | `X`, 32 bytes |
| -3 | `y` | `Y`, 32 bytes |

`TestExportOTAImageKey_PublicKeyAndCOSEKey` (`ota_image_keys_export_test.go:51`)
checks that the map holds those six labels and no other, that the bytes
are core deterministic CBOR, that `X || Y` is the created key's point, and
that the decoded COSE_Key verifies the board's `SignOTAImage` signature.

**Naming a version after a rotation.** The `kid` is the key ID, and it does
not change when the key rotates; the version is `KeyVersion`. A caller
names a version by the pair (`key_id`, `key_version`). `SignOTAImage`
reports the same `KeyVersion` for the version that signed
(`pkg/api/transport/types.go:671-672`), so a verifier picks the exported key
whose version matches. An export always returns the current version: after
a rotation it moves to the new version, with the new point
(`TestExportOTAImageKey_FollowsRotation`, `ota_image_keys_export_test.go:95`).
There is no request for an earlier version's public key, so a verifier that
must still accept images signed by an earlier version keeps that version's
export.

**Tenancy.** Each request's `TenantID` scopes the key
(`pkg/api/transport/types.go:650`, `:662`). Each transport fills it from the
caller (REST `pkg/api/rest/handlers_ota_image.go:114`, `:146`, `:173`; the
export over gRPC `pkg/api/grpc/service_ota_image.go:164` and over MCP
`pkg/api/mcp/handlers_ota_image.go:122`). Another tenant's board key is not
found (`TestExportOTAImageKey_TenantScoped`,
`ota_image_keys_export_test.go:116`).

**Errors.** The sentinels are in `pkg/xkms/errors.go`. `ErrInvalidBoardID`
and `ErrOTAImageAlgorithm` are wrapped in `ErrValidation`, so `errors.Is`
reaches the sentinel:

| Error | Returned when | REST | gRPC / Unix | MCP |
|---|---|---|---|---|
| `ErrInvalidBoardID` (`errors.go:201`) | malformed board id (`ota_image_keys.go:50`) | 400 | `InvalidArgument` | `-32602` |
| `ErrOTAImageAlgorithm` (`errors.go:205`) | algorithm other than ES256 (`:61`), or the board key is not P-256 (`:213`) | 400 | `InvalidArgument` | `-32602` |
| `ErrOTASignatureEncoding` (`errors.go:948`), matches `ErrInvalidSignature` | sign only: the backend's signature is not DER, or `r` or `s` is outside `[1, n-1]` (`ota_image_keys.go:221-233`) | 500 | `Internal` | error object |
| unknown board key | rotate, sign or export for a board with no key | 404 (`pkg/api/rest/handlers_ota_image_test.go:179`) | `NotFound` (`pkg/api/grpc/service_ota_image_test.go:177`) | not `-32602` (`pkg/api/mcp/handlers_ota_image_test.go:190`) |
| `ErrKeyAlreadyExists` | create for a board that has a key | 409 | `AlreadyExists` | error object |

- The `ErrValidation` rows map in each transport's `mapKeyOpError`
  (`pkg/api/rest/errors_keyops.go:142`,
  `pkg/api/grpc/errors_keyops.go:150`,
  `pkg/api/mcp/errors_keyops.go:190`).
- The `ErrKeyAlreadyExists` row follows the
  [status and error mapping](api.md#status-and-error-mapping).
- Over gRPC, a missing backend is `InvalidArgument`
  (`pkg/api/grpc/service_ota_image.go:37`). A key service that is not
  initialized is `Unavailable` (`:45`).
- xkmsctl does not repeat the validation. It wraps the server's error in
  `ErrCreateOTAImageKeyFailed`, `ErrRotateOTAImageKeyFailed`,
  `ErrSignOTAImageFailed` or `ErrExportOTAImageKeyFailed`
  (`cmd/xkmsctl/errors.go:838`, `:842`, `:846`, `:850`) and exits 1.

**Tests.** Each row names the first test of the file's OTA set.

| Layer | Tests |
|---|---|
| Service | `pkg/xkms/ota_image_keys_test.go:42` onwards; the export in `pkg/xkms/ota_image_keys_export_test.go:51` onwards |
| REST | `pkg/api/rest/handlers_ota_image_test.go:78` onwards: 200/201/400/404 |
| gRPC | `pkg/api/grpc/service_ota_image_test.go:57` onwards: `InvalidArgument`, `NotFound`, `Unavailable` |
| MCP | `pkg/api/mcp/handlers_ota_image_test.go:81` onwards |
| Client transports | `pkg/api/transport/{rest,quic,mcp,grpc,unix,embedded}/transport_ota_image_test.go`: each transport carries all four calls, and refuses an invalid board; grpc, unix and embedded also return `ErrNotConnected` before connecting |
| xkmsctl | `cmd/xkmsctl/key_ota_image_test.go:125` onwards: a refused board id or algorithm exits 1 with the typed sentinel |

## Error semantics

Typed errors only — `fmt.Errorf` is not used. The keystore vocabulary is
`pkg/xkms/errors.go`; representative values:

| Error | Returned when |
|---|---|
| `ErrKeyNotFound` | the key ID does not resolve in the named backend |
| `ErrKeyAlreadyExists` | `GenerateKey`/`ImportKey` on an occupied ID |
| `ErrInvalidKeyID` | malformed identifier |
| `ErrInvalidKeyType`, `ErrInvalidKeyAlgorithm`, `ErrUnsupportedKeyAlgorithm` | algorithm vocabulary violations |
| `ErrInvalidCurve`, `ErrInvalidHashFunction`, `ErrInvalidKDFAlgorithm` | parameter validation |
| `ErrInvalidSignature`, `ErrInvalidSignatureAlgorithm`, `ErrInvalidSignatureScheme` | verify-path validation |
| `ErrNoBackendsConfigured`, `ErrNoDefaultBackend`, `ErrDefaultBackendNotFound` | keystore construction |
| `ErrNotInitialized`, `ErrAlreadyInitialized` | lifecycle |
| `ErrSOPinRequired`, `ErrUserPinRequired`, `ErrPasswordRequired` | a hardware backend needs credentials first |

`ImportKey` returning `ErrKeyAlreadyExists` on an occupied ID was the documented
contract before it was the implemented one: until go-xkms#165 the software
backend's import wrote with a plain Put and replaced the existing key, reporting
success. Replacing a key is an explicit delete followed by an import.

The software backend decides presence by **reading** the key, not by
`storage.KeyExists` or `storage.SaveKeyIfAbsent`. Neither is usable across the
storage engines it runs on: `Exists` returns true for a key that was never
written on the file, pebble and qrdb engines, and `PutIfAbsent` fails on those
same engines with `embedded: TransactionServicer must not be nil` — which is
also why `GenerateKey` cannot run against them as constructed. `Get` is the one
primitive that separates present from absent everywhere, though not by the same
signal: the in-memory engine reports `storage.ErrNotFound`, while the
qrdb-backed engines report no error and no bytes. Both `Exists` and
`PutIfAbsent` behaviours are storage-layer defects filed separately.

Transport mapping is centralised so a given condition renders the same way on
every wire: `pkg/api/rest/errors_keyops.go`, `pkg/api/grpc/errors_keyops.go`,
`pkg/api/mcp/errors_keyops.go`, `pkg/xkms/errors_keyops.go`. Wrapping across
the SDK boundary uses `pkg/errs` (`errs.Message`, `errs.Detail`), and the SDK
side re-renders in `sdk/go/errors.go`.

**Every MCP handler decodes params through one helper (go-xkms#774, #783).**
`pkg/api/mcp/utils.go`'s `decodeParams` is the sole params-decode path: it
always returns a `*KeyOpError{Code: ErrCodeInvalidParams}`
(`pkg/api/mcp/errors_keyops.go`'s `KeyOpError`) on a `json.Unmarshal`
failure, so `InvokeMethod`/`mcpToolHandler` classifies malformed JSON as
Invalid params (`-32602`) rather than the internal fault an unclassified
`*errs.Wrapped` renders as. Every `pkg/api/mcp/handlers*.go` handler that
takes params calls it (`ssh.*`'s own `json.Unmarshal` + `mapSSHError`,
`errors_ssh.go`, is the one deliberate exception: it already produces the
same `*KeyOpError{ErrCodeInvalidParams}` outcome through a path that also
carries SSH's own NotFound/Duplicate/Mismatch codes, so it is not routed
through `decodeParams` too). `pkg/api/mcp/handlers_user.go`'s
`unmarshalUserParams` used to be a second such helper that returned a bare
`*errs.Wrapped` instead — every `user.*` malformed-params failure reached
the caller as an internal fault regardless of the request. It is deleted;
`user.*` handlers call `decodeParams` like every other handler.
`TestEveryHandler_MalformedParamsAreInvalidParams`
(`malformed_params_sweep_test.go`) drives every entry of `rpcMethods`
with unparsable JSON and asserts `-32602`, so a future handler that starts
decoding params without going through `decodeParams` fails that test by
name instead of silently reaching the caller as `-32603`.

**Not-found is a distinct MCP code (go-xkms#814).** `xkms.ErrKeyNotFound`,
`xkms.ErrBackendNotFound` (`errors_keyops.go`'s `keyOpSentinelCodes`), and a
`*qrdbsdk.UserNotFoundError` reached through `pkg/xkms.ErrUserOperation`
(`handlers_user.go`'s `mapUserError`) all classify onto
`sdkssh.JSONRPCCodeNotFound`, matching go-qrdb's own NotFound classification
of the identical `UserNotFoundError` type across its gRPC, QUIC, and MCP-
wire transports ("lower layers win"). See [api.md](api.md) §"Status and
error mapping" for the full code tables and the client-side reverse
mapping.

Five MCP handlers (`getTLSCertificate`, `getImportParameters`,
`importKeyMaterial`, `asymmetricEncrypt`, `asymmetricDecrypt`) refuse a
backend name before the operation runs. The name is resolved through the
service's `LookupBackend`, the same mechanism every other handler uses: a
backend name is a registry key, so a configured name that is not a
store-type keyword (`token-a`) is accepted, and a spelling the name
validation rejects (`SOFTWARE`) or a name that is not registered is refused.
That refusal is one typed error, `mcp.InvalidBackendError`: `errors.Is`
finds `mcp.ErrInvalidBackend`, it unwraps to the service's reason
(`xkms.ErrBackendNotFound` or `xkms.ErrBackendNameValidation`), it renders
as `invalid backend: <name>: <reason>`, and it is carried as a `KeyOpError`
with the JSON-RPC invalid-params code. A name that resolves is the backend
the operation runs against, viewed through the caller's tenant: the TLS
key and certificate are read from it, and the wrapping key and import
token for `importKeyMaterial` are issued by it. The default backend is used
only when no name is given.

**REST wire bodies.** The BYOK ceremony's REST request and response bodies
live in `pkg/api/rest/wire`, a leaf package the REST handlers alias and the
REST and QUIC client transports build by name, with the DER-to-PEM
translation of the wrapping key in one place; see [api.md](api.md) §"The
REST body spells the same fields the same way as MCP".

**Fail-closed paths:** export of a non-exportable key; any operation on a
sealed barrier; a tenant mismatch; an RBAC denial. Each returns an error
without touching backend state.

## Configuration

Server config is `pkg/config` (`config.go`). Ports live under `server:`:

```yaml
server:
  rest_port: 8443
  grpc_port: 9443
  quic_port: 8444
  mcp_port: 8445
  noise_port: 8447        # xkmsd-local.yaml only; see api.md §Port conflicts
```

Client defaults are `sdk/go/options.go`:

```go
DefaultTimeout      = 30 * time.Second
DefaultMaxRetries   = 3
DefaultRetryBackoff = 100 * time.Millisecond
DefaultPoolMinConns = 1
DefaultPoolMaxConns = 10
DefaultRESTAddress  = "http://localhost:8443"
DefaultGRPCAddress  = "localhost:9443"
DefaultQUICAddress  = "localhost:8444"
DefaultMCPAddress   = "localhost:9444"
```

`xkmsctl` persistent flags (`cmd/xkmsctl/root.go`) set the client side:
`--config`, `--backend` (default `software`), `--key-dir` (default
`xkms-data/keys`), `--output/-o` (default `text`), `--verbose/-v`,
`--transport`, `--server/-s`, `--tls-cert`,
`--tls-key`, `--tls-ca`, `--token`, `--spki-pin`, `--so-pin`,
`--pkcs11-module`, `--pkcs11-slot`, `--pkcs11-pin`.

Precedence: explicit flag → config file → built-in default.

## Persistence

Key metadata, software-backend blobs, certificates and CA blobs are all
stored through `go-qrdb/sdk/go`; go-xkms never imports go-objstore (see
`docs/datastore/engineering.md`, "CA blob storage"). go-xkms defines no schema of
its own beyond the key-ID encoding in `pkg/xkms/keyid.go`. Hardware and cloud
backends persist nothing locally — the device or the provider is the store, and
xkms holds only the handle.

Compatibility rule: the key-ID encoding is a wire contract. Changing it is a
breaking change and requires a coordinated release
(`conventions/release-versioning.md`).

## Test strategy

- **Unit** — per-package under `pkg/xkms/*_test.go`; the composite has
  dedicated key, crypto, cert, seal and key-ID suites.
- **Integration** — `test/integration/xkms`, `test/integration/crypto`,
  `test/integration/signing`, plus per-backend suites (`awskms`, `gcpkms`,
  `azurekv`, `vault`, `pkcs11`, `pkcs8`, `tpm2`, `quantum`).
- **Multiprotocol parity** — `test/integration/api/commands/commands.go`
  defines `CommandDefinition` entries that the table-driven runner
  (`runner.go`) executes across every protocol. Key-management definitions
  present today: `key-generate-rsa`, `key-generate-ecdsa`,
  `key-generate-ed25519`, `key-generate-symmetric-exportable`,
  `key-generate-symmetric-sensitive`, `key-list`, `key-info`, `key-delete`,
  `key-sign`, `key-verify`, `backends-list`, `version`.
  **Gap:** `cli.md` documents more verbs than have definitions — see the note
  at the end of `cli.md`.
- **Fault injection seams** — the per-backend constructors in
  `pkg/server/backend_<backend>.go` accept substitutes; `pkg/testutil` and
  `pkg/testing` hold fixtures.

## Observability

Requests carry a correlation ID injected by `pkg/correlation`'s HTTP middleware
and gRPC interceptors (`pkg/correlation/middleware.go`), which the REST router
and gRPC server install.
Metrics are `pkg/metrics`. Audit records for key operations are written through
`pkg/audit` — see [`../audit-log/engineering.md`](../audit-log/engineering.md).
