# OATH TOTP/HOTP — Engineering

> **Status: NORMATIVE** · Feature: `oath` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

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
	// secret is unexported; see SetSecret/SecretString.
}
func NewCredential(name, issuer, otpType string) (*Credential, error)
func NewCredentialFromManualEntry(accountName, issuer, secret string) (*Credential, error)
func ParseURI(uri string) (*Credential, error)
func GenerateSecret(length int) (string, error)
func (c *Credential) SetSecret(secret string) error
func (c *Credential) SecretString() string
func (c *Credential) HasSecret() bool
func (c *Credential) ToURI() string
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

// composite_store.go -- see architecture.md: not wired into the CLI or GUI today.
type CompositeStore struct{ /* routes by Credential.BackendID */ }
func NewCompositeStore(defaultStore string) *CompositeStore
func (c *CompositeStore) Register(backendID string, store Store)
func (c *CompositeStore) Unregister(backendID string)
func (c *CompositeStore) SetDefault(backendID string)
```

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
  `SetSecret`/`SecretString` are the only crossing points, and JSON
  marshaling round-trips through the same protection (go-xkms#210).
- **`crypto/hmac`'s internal ipad/opad copy during HMAC computation is the
  one accepted residue outside protected memory** — `crypto/hmac` exposes no
  way to wipe it, and hand-rolling HMAC to avoid that would forfeit FIPS
  validation on the exact path this package makes FIPS-safe. Documented at
  the call site in `Generator.GenerateCounter`
  (`xkey/pkg/oath/generator.go:98`).
- **Under `GODEBUG=fips140=only`, SHA-1 and secrets shorter than 112 bits
  (14 bytes) are refused with a typed error, not a stdlib panic.**
  `shortHMACKeysRefused` (`generator.go:50`) probes the running process once
  to decide which mode is active; see `ErrAlgorithmNotFIPSApproved` and
  `ErrSecretTooShortForFIPS` below. SHA-1 stays the non-FIPS default: RFC
  6238 and every mainstream authenticator (Google Authenticator, Authy,
  1Password, the `otpauth://` default) assume it.
- **`CompositeStore` is a complete, tested implementation with no current
  caller** outside `pkg/oath` itself (see architecture.md). It is not a
  stub — every method has a real implementation — but nothing constructs
  one yet.

## Errors

`xkey/pkg/oath` (`credential.go`, `store.go`, `composite_store.go`,
`generator.go`):

| Sentinel | Meaning |
|---|---|
| `ErrInvalidCredential`, `ErrInvalidSecret`, `ErrInvalidType`, `ErrInvalidAlgorithm`, `ErrInvalidDigits`, `ErrInvalidPeriod`, `ErrInvalidURI` | `Credential.Validate`/`ParseURI` field validation |
| `ErrAlgorithmNotFIPSApproved` | Credential's algorithm (SHA-1) is refused under `GODEBUG=fips140=only` |
| `ErrSecretTooShortForFIPS` | Credential's secret is under 112 bits under `GODEBUG=fips140=only` |
| `ErrCredentialExists`, `ErrCredentialNotFound` | Store add/lookup |
| `ErrProtectedMemory` | mlocked secret allocation failed (never falls back to the heap) |
| `ErrStoreNotInitialized`, `ErrStoreClosed` | `FileStore`/`MemoryStore` lifecycle |
| `ErrStoreNotFound` | `CompositeStore`: no store registered for the credential's `BackendID` |
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
| Store location | `--store` flag (`./data/oath.json` default) → barrier-or-file decision via `resolveSecretStoreBackend` when `--store` is left at default | See architecture.md's "At-rest encryption" |
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
| `xkey/cmd/xkey/cmd/oath_test.go`, `oath_barrier_test.go`, `oath_run_test.go`, `oath_secret_helper_test.go` | `ble codec_json` | CLI verbs, barrier-vs-file store resolution, generate/list/remove flows |

Run the package tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' ./pkg/oath/...
```

Run the CLI tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' -run TestOATH ./cmd/xkey/cmd/...
```
