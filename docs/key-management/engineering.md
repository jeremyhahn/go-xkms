# Key Management — Engineering Contract

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-09-10

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

## Invariants

- **A key ID is scoped to `{tenant, backend}`.** The same string in two
  backends names two different keys; `ListKeys` always takes a backend.
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
- **Wrap/unwrap by ID never materialises plaintext outside the service.**
  `WrapKeyByID` reads the KEK and the target inside the process and returns
  only ciphertext.
- **Rotation preserves the key ID.** Callers keep referring to the same
  identifier; the backend decides how versions are represented.
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
and reports P-256 for every ECDSA key; copy, migrate and PKCS#11 `C_UnwrapKey`
all reach the validator through attributes built that way, so comparing curves
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
`--transport` (`--protocol/-P` is deprecated), `--server/-s`, `--tls-cert`,
`--tls-key`, `--tls-ca`, `--token`, `--spki-pin`, `--so-pin`,
`--pkcs11-module`, `--pkcs11-slot`, `--pkcs11-pin`.

Precedence: explicit flag → config file → built-in default.

## Persistence

Key metadata and software-backend blobs are stored through `go-qrdb/sdk/go`;
certificate and serial blobs go to go-objstore. go-xkms defines no schema of
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

Requests carry a correlation ID injected by `pkg/api/rest/middleware_correlation.go`
and `pkg/api/grpc/interceptor_correlation.go`, built on `pkg/correlation`.
Metrics are `pkg/metrics`. Audit records for key operations are written through
`pkg/audit` — see [`../audit-log/engineering.md`](../audit-log/engineering.md).
