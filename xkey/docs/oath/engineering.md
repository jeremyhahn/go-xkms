# OATH TOTP/HOTP — Engineering

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-10-01

See [architecture.md](architecture.md) for the component map before reading
this document.

## Exported surface: `xkey/pkg/oath`

```go
// credential.go
type Credential struct {
	ID, Name, Issuer, AccountName string
	Type, Algorithm                string // "totp"|"hotp"; "SHA1"|"SHA256"|"SHA512"
	Digits, Period                 int
	Counter                        uint64
	CreatedAt                      time.Time
	BackendID                      string // empty == default store
	// secret is unexported; see SetSecret/Secret.
}
func NewCredential(name, issuer, otpType string) (*Credential, error)
func NewCredentialFromManualEntry(accountName, issuer, secret string) (*Credential, error)
func ParseURI(uri string) (*Credential, error)
func GenerateSecret(length int) (string, error)
func (c *Credential) SetSecret(secret []byte) error // copies; the caller wipes secret
func (c *Credential) Secret() ([]byte, error)       // caller-owned copy, nil when unset
func (c *Credential) HasSecret() bool
func (c *Credential) ToURI() (string, error) // embeds the secret
func (c *Credential) Validate() error
func (c *Credential) MarshalJSON() ([]byte, error)
func (c *Credential) UnmarshalJSON(data []byte) error

// generator.go
type Generator struct{ /* wraps a *Credential */ }
func NewGenerator(cred *Credential) (*Generator, error)
func (g *Generator) Generate() (string, error)
func (g *Generator) GenerateAt(t time.Time) (string, error)
func (g *Generator) GenerateCounter(counter uint64) (string, error)
func (g *Generator) Validate(code string) error
func (g *Generator) ValidateWithSkew(code string, skew int) error
func (g *Generator) TimeRemaining() int
func (g *Generator) Counter() uint64
func (g *Generator) IncrementCounter()

// store.go
type Store interface {
	Add(cred *Credential) error
	Get(idOrName string) (*Credential, error)
	List() ([]*Credential, error)
	Update(cred *Credential) error
	Delete(idOrName string) error
	Close() error
}
type FileStore struct{ /* JSON file */ }
func NewFileStore(path string) (*FileStore, error)
type MemoryStore struct{ /* in-memory, for tests */ }
func NewMemoryStore() *MemoryStore

// backend_store.go
type BackendStore struct{ /* wraps xkms.StorageBackend */ }
func NewBackendStore(backend xkms.StorageBackend, prefix string) (*BackendStore, error)

// composite_store.go
type CompositeStore struct{ /* routes by Credential.BackendID */ }
func NewCompositeStore(defaultStore string) *CompositeStore
func (c *CompositeStore) Register(backendID string, store Store)
func (c *CompositeStore) Unregister(backendID string)
func (c *CompositeStore) SetDefault(backendID string)

// backends.go -- one partition per OATH-capable backend (architecture.md)
const DefaultBackendID = "software"
func OpenStores(storage xkms.StorageBackend, path string, ids []string, defaultID string) (*CompositeStore, error)
func FilePartitionPath(path, id string) (string, error)

// errors.go
type BackendError struct{ Err error; BackendID string }
```

The backend IDs come from `backendregistry.ConfiguredFor(cfg, CapOATH)`
(`xkey/pkg/backendregistry/capabilities.go:32`), which both the CLI and the
GUI call.

## Exported surface: GUI service

`xkey/pkg/gui/services.OATHService` (`oath_service.go`):

```go
func NewOATHService(store oath.Store) *OATHService
func (s *OATHService) SetContext(ctx context.Context)
func (s *OATHService) SetStore(store oath.Store)
func (s *OATHService) SetAuditLogger(l audit.Logger)
func (s *OATHService) ListAccounts() ([]OATHAccount, error)
func (s *OATHService) AddAccount(uri string) (*OATHAccount, error)
func (s *OATHService) AddAccountManual(accountName, issuer, secret string) (*OATHAccount, error)
func (s *OATHService) AddAccountFromURI(uri string) (*OATHAccount, error)
func (s *OATHService) DeleteAccount(id string) error
func (s *OATHService) GenerateTOTP(id string) (*TOTPCode, error)
func (s *OATHService) GenerateHOTP(id string) (*HOTPCode, error)
func (s *OATHService) ScanQR(displayIndex int) (*QRScanResult, error)
```

`GenerateTOTP` is the same method `xkey/pkg/gui/services.AutoFillService`
calls for browser-extension TOTP autofill (`autofill/engineering.md`).

## Exported surface: `xkey/pkg/qrscan`

```go
func NewScanner() *Scanner
func NumDisplays() int
func (s *Scanner) ScanScreen(displayIndex int) ([]*ScanResult, error)
func (s *Scanner) ScanAllScreens() ([]*ScanResult, error)
func (s *Scanner) ScanImage(img image.Image) ([]*ScanResult, error)
func ScanScreenForOTP() (string, error)
```

## Invariants

- **The shared secret is never a plain Go string in `Credential`.** It lives
  in an unexported `*secure.Buffer` (mlocked, guard-paged memory);
  `SetSecret`/`Secret` are the only crossing points, and JSON
  marshaling round-trips through the same protection (go-xkms#210).
- **`crypto/hmac`'s internal ipad/opad copy during HMAC computation is the
  one accepted residue outside protected memory** — `crypto/hmac` exposes no
  way to wipe it, and hand-rolling HMAC to avoid that would forfeit FIPS
  validation on the exact path this package makes FIPS-safe. Documented at
  the call site in `Generator.GenerateCounter`
  (`xkey/pkg/oath/generator.go:73`).
- **Under `GODEBUG=fips140=only`, SHA-1 and secrets shorter than 112 bits
  (14 bytes) are refused with a typed error, not a stdlib panic.**
  `fipsMode` (`xkey/pkg/oath/fips.go:22`) is `crypto/fips140.Enforced`, the
  flag `crypto/hmac` itself checks, so the package refuses exactly what the
  stdlib refuses (owner ruling 116). Under `fips140=on` the stdlib still
  computes both, so they are accepted there. See `ErrAlgorithmNotFIPSApproved` and
  `ErrSecretTooShortForFIPS` below. SHA-1 stays the non-FIPS default: RFC
  6238 and every mainstream authenticator (Google Authenticator, Authy,
  1Password, the `otpauth://` default) assume it.
- **A credential ID or name is unique across every backend.**
  `CompositeStore.Get`/`Delete` search all partitions, so `Add` refuses a
  duplicate held by any backend with `ErrCredentialExists`
  (`xkey/pkg/oath/composite_store.go:227`). `Add` holds the write lock
  across that check and the insertion, so concurrent adds of one name to
  two backends cannot both succeed (`composite_store.go:70`).
- **A partition file is named after its store file** (`<stem>@<id><ext>`,
  `xkey/pkg/oath/backends.go:75`), and a store path containing `@` in its
  file name is refused (`ErrInvalidStorePath`), so two stores never share or
  alias a partition.
- **The `software` partition is the historical location** (`oath/` keys,
  `oath.json`), so credentials with no `BackendID` stay reachable
  (`xkey/pkg/oath/backends.go:28`).

## Errors

`xkey/pkg/oath` (`credential.go`, `store.go`, `composite_store.go`,
`backends.go`, `generator.go`):

| Sentinel | Meaning |
|---|---|
| `ErrInvalidCredential`, `ErrInvalidSecret`, `ErrInvalidType`, `ErrInvalidAlgorithm`, `ErrInvalidDigits`, `ErrInvalidPeriod`, `ErrInvalidURI` | `Credential.Validate`/`ParseURI` field validation |
| `ErrAlgorithmNotFIPSApproved` | Credential's algorithm (SHA-1) is refused under `GODEBUG=fips140=only` |
| `ErrSecretTooShortForFIPS` | Credential's secret is under 112 bits under `GODEBUG=fips140=only` |
| `ErrCredentialExists`, `ErrCredentialNotFound` | Store add/lookup |
| `ErrProtectedMemory` | mlocked secret allocation failed (never falls back to the heap) |
| `ErrStoreNotInitialized`, `ErrStoreClosed` | `FileStore`/`MemoryStore` lifecycle |
| `ErrStoreNotFound` | `CompositeStore`: no store registered for the credential's `BackendID`, wrapped in `*BackendError` naming it |
| `ErrInvalidBackendID` | `OpenStores`: a backend ID that cannot name a key prefix or file, wrapped in `*BackendError` |
| `ErrBackendStoreOpen` | `OpenStores`: one backend's partition failed to open, wrapped in `*BackendError` |
| `ErrInvalidStorePath` | `OpenStores`/`FilePartitionPath`: an empty store path, or one whose file name contains `@` |
| `ErrInvalidCode`, `ErrCodeExpired` | `Generator.Validate`/`ValidateWithSkew` |

`xkey/pkg/gui/services` (`oath_service.go`): `ErrOATHStoreNotSet`,
`ErrOATHInvalidURI`, `ErrOATHInvalidID`, `ErrOATHAccountNotFound`,
`ErrOATHGenerateFailed`, `ErrOATHQRNotFound`, `ErrOATHQRInvalidURI`,
`ErrOATHQRScanFailed`, `ErrOATHMissingSecret`.

`cmd/xkey/cmd` (`oath.go`): `ErrOATHMissingName`, `ErrOATHMissingSecret`,
`ErrOATHMissingCredential`, `ErrOATHMissingRemoveArg`,
`ErrOATHStoreOpenFailed`, `ErrOATHInvalidURI`, `ErrOATHInvalidCredential`,
`ErrOATHAddFailed`, `ErrOATHListFailed`, `ErrOATHGenerateFailed`,
`ErrOATHDeleteFailed`, `ErrOATHCredentialNotFound`, `ErrOATHScanFailed`,
`ErrOATHNoQRFound`, `ErrOATHMultipleQRFound`.

## Configuration

| Setting | Resolution | Notes |
|---|---|---|
| Store location | `--store` flag (unset default resolves to `~/.xkey/data/oath.json` via `resolveDataDir`, `datadir.go`, go-xkms#929) → barrier-or-file decision via `resolveSecretStoreBackend` when `--store` is left at default | See architecture.md's "At-rest encryption" |
| OATH backends | `backends.local` entries whose category offers `oath` (`software`, `pkcs11`), plus `software` | `backendregistry.ConfiguredFor` |
| Default OATH backend | `xkey oath add --backend` → `backends.defaults.oath` → `software` | An unknown `--backend` is refused with `*oath.BackendError` |
| Barrier password | `--barrier-password` → `--barrier-password-file` → `XKEY_BARRIER_PASSWORD` → interactive prompt | Only consulted when the default store resolves to the barrier |

## Tests

| File | Tags | Covers |
|---|---|---|
| `xkey/pkg/oath/credential_test.go` | (none) | `Credential` construction, validation, URI round-trip, secret protection |
| `xkey/pkg/oath/secret_protected_test.go`, `secret_first_assignment_test.go`, `secret_helper_test.go` | (none) | mlocked-buffer invariants (go-xkms#210) |
| `xkey/pkg/oath/generator_test.go` | (none) | RFC 4226/6238 vectors, skew validation |
| `xkey/pkg/oath/fips_gate_test.go` | (none) | FIPS-mode algorithm/secret-length refusal |
| `xkey/pkg/oath/store_test.go` | (none) | `FileStore`/`MemoryStore` CRUD |
| `xkey/pkg/oath/backend_store_test.go` | (none) | `BackendStore` over a fake `xkms.StorageBackend` |
| `xkey/pkg/oath/composite_store_test.go` | (none) | `CompositeStore` routing/merge, unregistered-backend error |
| `xkey/pkg/oath/backends_test.go` | (none) | partition prefixes/files, legacy credentials on `software`, invalid IDs, cross-backend duplicates (concurrent, under `-race`), partition files named after the store file, two stores in one directory isolated |
| `xkey/pkg/backendregistry/capabilities_test.go` | (none) | `ConfiguredFor` backend selection and default |
| `xkey/cmd/xkey/cmd/oath_test.go`, `oath_barrier_test.go`, `oath_run_test.go`, `oath_secret_helper_test.go` | `ble codec_json` | CLI verbs, barrier-vs-file store resolution, generate/list/remove flows |
| `xkey/test/integration/oath/oath_test.go` | `integration` | the `xkey` binary end to end; `TestOATHCLI_MultiBackend` drives `--backend` across two backends via `--config` |
| `xkey/cmd/xkey/cmd/oath_multibackend_864_test.go` | `ble codec_json` | `--backend` add/list/generate/remove over two backends (file and barrier), unknown-backend refusal, existing default-backend credentials, a `token1` credential through `xkey backup` create/restore and listed by the extension server |

Run the package tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' ./pkg/oath/...
```

Run the CLI tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' -run TestOATH ./cmd/xkey/cmd/...
```
