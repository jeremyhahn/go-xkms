# Key Management — Engineering Contract

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-08-19

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

Transport mapping is centralised so a given condition renders the same way on
every wire: `pkg/api/rest/errors_keyops.go`, `pkg/api/grpc/errors_keyops.go`,
`pkg/api/mcp/errors_keyops.go`, `pkg/xkms/errors_keyops.go`. Wrapping across
the SDK boundary uses `pkg/errs` (`errs.Message`, `errs.Detail`), and the SDK
side re-renders in `sdk/go/errors.go`.

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
- **Fault injection seams** — backend factories in `pkg/server/backend_factory*.go`
  accept substitutes; `pkg/testutil` and `pkg/testing` hold fixtures.

## Observability

Requests carry a correlation ID injected by `pkg/api/rest/middleware_correlation.go`
and `pkg/api/grpc/interceptor_correlation.go`, built on `pkg/correlation`.
Metrics are `pkg/metrics`. Audit records for key operations are written through
`pkg/audit` — see [`../audit-log/engineering.md`](../audit-log/engineering.md).
