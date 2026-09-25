# Static Passwords — Engineering

> **Status: NORMATIVE** · Feature: `password` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

See [architecture.md](architecture.md) for the store hierarchy and the
"store location vs. session state" split before reading this document.

## Exported surface: store (root module, reached via `sdk/go`/`xkey/pkg/staticpw`)

`xkey/pkg/staticpw/lib.go` re-exports the root module's `pkg/staticpw`
through `sdk/go/staticpw.go` under a flat `xkms.StaticPassword*` namespace,
per the SDK boundary in `xkey/CLAUDE.md`:

```go
// xkey/pkg/staticpw (all type aliases / re-exported vars)
type StaticPassword = xkms.StaticPassword
type Store = xkms.StaticPasswordStore
type BackendStore = xkms.StaticPasswordBackendStore
type ExpiryChecker = xkms.StaticPasswordExpiryChecker
type TeamStore = xkms.StaticPasswordTeamStore       // multi-tenant, no xkey CLI/GUI surface
type TeamEntity = xkms.StaticPasswordTeamEntity
type DAOTeamStore = xkms.StaticPasswordDAOTeamStore

var NewStore = xkms.NewStaticPasswordStore
var NewTenantStore = xkms.NewStaticPasswordTenantStore
var NewExpiryChecker = xkms.NewStaticPasswordExpiryChecker
var GeneratePassword = xkms.GenerateStaticPassword
var GenerateID = xkms.GenerateStaticPasswordID
var NewDAOTeamStore = xkms.NewStaticPasswordDAOTeamStore
```

`StaticPassword` fields (`go-xkms/pkg/staticpw/types.go:28`): `ID`, `Name`,
`Title`, `Username`, `Password`, `URL`, `MatchPatterns []string`, `Notes`,
`FolderPath`, `ExpiresAt time.Time`, `CreatedAt`/`UpdatedAt`, `ReadOnly
bool`.

`Store` interface (`go-xkms/pkg/staticpw/store.go:52`): `Add`, `Get`,
`List`, `Update`, `Delete`, `ForceDelete`, `ListByFolder`,
`ListByFolderDirect`, `ListFolders`, `CreateFolder`, `RemoveFolder`,
`MoveToFolder`, `Close`. `BackendStore` (`store.go:102`) is the concrete
type every constructor above returns.

Constants: `xkms.StaticPasswordCharsetAll`,
`StaticPasswordCharsetAlphanumeric`, `StaticPasswordDefaultLength` (32),
`StaticPasswordMinLength`/`MaxLength` (8/128) — `sdk/go/staticpw.go:70`.

## Exported surface: CLI (`cmd/xkey/cmd/password.go`, `touch.go`)

```go
// password.go
type PasswordStoreClientService interface {
	Connect(ctx context.Context) error
	Close() error
	PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx context.Context) error
	PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error
}
func openPasswordStore(storePath string) (*xkms.StaticPasswordBackendStore, error)
func connectPasswordStore() (PasswordStoreClientService, error)
type PasswordStoreError struct{ Operation, Message string; Err error }
```

`transport.PasswordService`, `PasswordStoreUnlockRequest`,
`PasswordStoreStatusResponse`, `PasswordStoreSetAccessModeRequest`
(`sdk/go/transport/client.go:34`, `sdk/go/transport/types.go:193-195`) are
the wire types the CLI's session verbs and `StaticPasswordService` both use
to talk to an `xkmsd` server.

## Exported surface: GUI (`pkg/gui/services/staticpw_service.go`)

```go
func NewStaticPasswordService(store staticpw.Store) *StaticPasswordService
func (s *StaticPasswordService) SetContext(ctx context.Context)
func (s *StaticPasswordService) SetStore(store staticpw.Store)
func (s *StaticPasswordService) SetClient(c transport.Client)
func (s *StaticPasswordService) SetAuditLogger(l audit.Logger)

// CRUD
func (s *StaticPasswordService) ListPasswords() ([]StaticPasswordEntry, error)
func (s *StaticPasswordService) GetPassword(idOrName string) (*StaticPasswordEntry, error)
func (s *StaticPasswordService) AddPassword(params AddPasswordParams) (*StaticPasswordEntry, error)
func (s *StaticPasswordService) UpdatePassword(params UpdatePasswordParams) error
func (s *StaticPasswordService) DeletePassword(idOrName string) error
func (s *StaticPasswordService) DeletePasswordForce(idOrName string) error
func (s *StaticPasswordService) GeneratePassword(length int, charset string) (string, error)
func (s *StaticPasswordService) SearchPasswords(query string) ([]StaticPasswordEntry, error)

// Folders
func (s *StaticPasswordService) ListFolders() ([]string, error)
func (s *StaticPasswordService) CreateFolder(path string) error
func (s *StaticPasswordService) ListPasswordsByFolder(folderPath string) ([]StaticPasswordEntry, error)
func (s *StaticPasswordService) MovePassword(id, folderPath string) error
func (s *StaticPasswordService) RenameFolder(oldPath, newPath string) error
func (s *StaticPasswordService) DeleteFolder(folderPath string) error

// Backup / restore (encrypted file, GUI-only)
func (s *StaticPasswordService) BackupPasswords(filePath string, encrypt bool, algorithm, password string) error
func (s *StaticPasswordService) RestorePasswords(filePath string, encrypted bool, algorithm, password string) (int, error)
func (s *StaticPasswordService) SaveBackupFileAs() (string, error)
func (s *StaticPasswordService) OpenBackupFileDialog() (string, error)

// Import (KeePass KDBX / CSV / XML, GUI-only; xkey/pkg/pwimport)
func (s *StaticPasswordService) OpenImportFileDialog() (string, error)
func (s *StaticPasswordService) PreviewImport(params ImportParams) (*ImportPreviewResult, error)
func (s *StaticPasswordService) ImportPasswords(params ImportParams) (*ImportResult, error)
func (s *StaticPasswordService) GetSupportedImportFormats() []string

// Session (talks to an xkmsd server via transport.Client, same as the CLI)
func (s *StaticPasswordService) Unlock(pin string) error
func (s *StaticPasswordService) Lock() error
func (s *StaticPasswordService) GetStoreStatus() (*PasswordStoreStatus, error)
func (s *StaticPasswordService) SetAccessMode(mode string) error
func (s *StaticPasswordService) TryAutoUnlock() error
```

`StaticPasswordEntry` mirrors `StaticPassword` plus computed fields
(`IsExpired`, `DaysUntilExpiry`) for the frontend
(`staticpw_service.go:89`).

## Exported surface: virtual keyboard (`pkg/keyboard`)

USB Boot Protocol keyboard over Linux UHID: `VendorIDKeyboard = 0xF1D0`,
`ProductIDKeyboard = 0x0004` (`pkg/keyboard/keyboard.go:30`). Types keystrokes
with a 5ms inter-keystroke delay; supports the printable-ASCII US layout.
Driven by `xkey touch` and `xkey password type` through the daemon's IPC
`touch`/`type_password` messages — see
[autofill/engineering.md](../autofill/engineering.md) for the IPC message
type constants shared with the extension protocol.

## Invariants

- **The store's location and its session state are answered by different
  authorities.** `list`/`status`/`add`/`get`/`remove` never require an
  `xkmsd` server; `unlock`/`lock`/`access-mode`, and `status --source
  xkmsd`, always do (`cmd/xkey/cmd/password.go:120-122`, doc comment on
  `PasswordCmd`).
- **Password values never cross the daemon IPC socket.**
  `resolvePasswordList` returns `ErrPasswordValuesNotOverIPC` before ever
  asking the daemon when `--show-passwords` is set
  (`password.go`, `resolvePasswordList`); only the on-disk path
  (`--source disk`) can reveal a value.
- **`EncryptedStore`/`PINAccessStore`/`SessionStore` are not reachable from
  `xkey`.** They are complete, tested root-module types, but no CLI command
  or GUI service constructs one — see architecture.md. Do not assume a
  field-level `ENC:` prefix appears in an `xkey`-written entry.
- **A read of a listed password's plaintext is defused after display.**
  The CLI wraps each on-disk value in a `*secure.Secret` and calls
  `entry.Password.Destroy()` immediately after writing it
  (`password.go`, `runPasswordList`) — it is never held as a bare Go string
  longer than the write.

## Errors

`cmd/xkey/cmd/password.go`:

| Sentinel | Meaning |
|---|---|
| `ErrPasswordMissingName`, `ErrPasswordMissingSource`, `ErrPasswordMutuallyExclusive` | `add` argument validation |
| `ErrPasswordMissingRemoveArg`, `ErrPasswordMissingGetArg`, `ErrPasswordMissingTypeArg` | Missing positional argument |
| `ErrPasswordStoreOpenFailed`, `ErrPasswordAddFailed`, `ErrPasswordListFailed`, `ErrPasswordGetFailed`, `ErrPasswordDeleteFailed`, `ErrPasswordGenerateFailed` | Store operation failures |
| `ErrPasswordNotFound` | Lookup miss |
| `ErrPasswordTypeFailed` | `type`/`touch` IPC failure |
| `ErrPasswordUnlockFailed`, `ErrPasswordLockFailed`, `ErrPasswordStatusFailed`, `ErrPasswordAccessModeFailed` | Session verb failures against `xkmsd` |
| `ErrPasswordInvalidMode`, `ErrPasswordMissingMode` | `access-mode` argument validation |
| `ErrPasswordMissingPIN` | `unlock` called with no `--pin` |
| `ErrPasswordConnectFailed` | Could not connect to the `xkmsd` session server |
| `ErrPasswordValuesNotOverIPC` | `--show-passwords` requested against the daemon; re-run with `--source disk` |

`go-xkms/pkg/staticpw` (`sdk/go/staticpw.go:83-116`, re-exported as
`xkms.StaticPassword*`): `ErrStaticPasswordEmpty`,
`ErrStaticPasswordFolderEmpty`, `ErrStaticPasswordGenerateFailed`,
`ErrStaticPasswordInvalidCharset`, `ErrStaticPasswordInvalidLength`,
`ErrStaticPasswordInvalidName`, `ErrStaticPasswordInvalid`,
`ErrStaticPasswordMarshalFailed`, `ErrStaticPasswordMoveToSameFolder`,
`ErrStaticPasswordExists`, `ErrStaticPasswordNotFound`,
`ErrStaticPasswordReadOnly`, `ErrStaticPasswordStoreClosed`,
`ErrStaticPasswordUnmarshalFailed`.

`pkg/gui/services/staticpw_service.go`: `ErrStaticPWStoreNotSet`,
`ErrStaticPWInvalidID`, `ErrStaticPWInvalidName`,
`ErrStaticPWInvalidFolderPath`, `ErrStaticPWInvalidExpiresAt`,
`ErrStaticPWReadOnly`, `ErrStaticPWNoClient`,
`ErrStaticPWInvalidAccessMode`, `ErrStaticPWInvalidGenerateLength`,
`ErrStaticPWBarrierSealed`.

## Configuration

| Setting | Resolution | Notes |
|---|---|---|
| Store path | `--store` flag (unset default resolves to `~/.xkey/data/staticpw` via `featureDataDir`, `datadir.go`, go-xkms#929) | Same flag name across `add`/`list`/`get`/`remove`/`status` |
| `--source` (`list`) | `auto`→ daemon, then disk | `daemon`/`disk` force one |
| `--source` (`status`) | `auto`→ daemon, then disk; `xkmsd` reads the session server | The only verb that accepts `xkmsd` |
| `xkmsd` endpoint | `--xkmsd-url` / `XKMSD_URL` / config, resolved by `newXKMSdClient` (shared helper, `xkmsd_client.go`) | Required for `unlock`/`lock`/`access-mode`, and `status --source xkmsd` |
| `fido2` daemon's password store | `--password-store` flag only (unset default resolves to the same `~/.xkey/data/staticpw`, go-xkms#929) | `xkey fido2` opens this store for `touch`/`password type` requests. `viper.BindPFlag("fido2.password_store", ...)` (`fido2.go:436`) is on the global Viper singleton, which is never wired to `AutomaticEnv`/`SetEnvPrefix`, so `XKEY_FIDO2_PASSWORD_STORE` does nothing today (go-xkms#871) |

## Tests

| File | Tags | Covers |
|---|---|---|
| `go-xkms/pkg/staticpw/*_test.go` (root module) | (none) | `StaticPassword` validation, `BackendStore`/`EncryptedStore`/`PINAccessStore`/`SessionStore`/team/tenant behavior |
| `xkey/cmd/xkey/cmd/password_test.go`, `password_ssh_cert_test.go` | `ble codec_json` | CLI verbs, `--source` resolution, IPC-vs-disk list/status behavior |
| `xkey/cmd/xkey/cmd/touch_test.go` | `ble codec_json` | `xkey touch` IPC round-trip |
| `xkey/pkg/gui/services/staticpw_service_test.go` | (none) | GUI CRUD, folders, backup/restore, import, session verbs |
| `xkey/pkg/pwimport/*_test.go` | (none) | KDBX/CSV/XML parsers |

Run the CLI tests:

```
cd xkey && GOWORK=off go test -tags 'ble codec_json' -run TestPassword ./cmd/xkey/cmd/...
```

Run the GUI service tests:

```
cd xkey && GOWORK=off go test ./pkg/gui/services/... -run TestStaticPassword
```
