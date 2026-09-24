# Secret Service — Engineering Contract

> **Status: NORMATIVE** · Feature: `secret-service` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Exported surface

Package `github.com/jeremyhahn/go-xkms/xkey/pkg/secretservice`.

```go
func NewDaemon(store xkms.StaticPasswordStore, barrier *xkms.Barrier,
    config *ServiceConfig, logger *slog.Logger) (*Daemon, error)

func (d *Daemon) SetUnlockFunc(fn UnlockFunc)
func (d *Daemon) SetAuditLogger(l audit.Logger)
func (d *Daemon) Start() error
func (d *Daemon) Stop() error
func (d *Daemon) IsRunning() bool

type UnlockFunc func(ctx context.Context) (xkms.SealCredentials, error)
```

`store` and `barrier` must be non-nil (`ErrNilPasswordStore` /
`ErrNilBarrier`); `barrier` is this process's lock (see architecture.md), so
a daemon without one could not honor `Lock`/`Unlock`/the `Locked` property
at all. `config` defaults to `DefaultConfig()`, which sets `Bus: "session"`.
There is no `AutoUnlock` option — see architecture.md's "Rejected
alternative: auto-unlock".

`UnlockFunc` is supplied by the caller wiring the daemon (the CLI verb, or a
future GUI toggle) so this package stays free of terminal/GUI dependencies.
A nil `UnlockFunc` means every `Prompt` created while sealed resolves
dismissed — the daemon still runs and still reports every collection
`Locked`, it just cannot unlock interactively.

## Object model and D-Bus paths

| Interface | Object path shape | Backed by |
|---|---|---|
| `org.freedesktop.Secret.Service` | `/org/freedesktop/secrets` | `Daemon` itself |
| `org.freedesktop.Secret.Collection` | `/org/freedesktop/secrets/collection/<folder>` | one per `pkg/staticpw` folder (`default` for `""`) |
| `org.freedesktop.Secret.Item` | `<collection path>/<hex password ID>` | one `StaticPassword` |
| `org.freedesktop.Secret.Session` | `/org/freedesktop/secrets/session/<n>` | `SessionInfo` |
| `org.freedesktop.Secret.Prompt` | `/org/freedesktop/secrets/prompt/<n>` | `PromptInfo` |

Collection and item objects are exported lazily: `Start` always exports the
default collection, and everything else (existing folders/items on an
already-unsealed barrier, or newly created ones) via `exportCollection` /
`exportItem`, which are idempotent (safe to call more than once for the same
path — godbus replaces the handler rather than erroring).

**While sealed, nothing beyond the default collection can be exported**:
`pkg/staticpw`'s `List`/`ListFolders` themselves fail against a sealed
barrier (the whole KV store is opaque encrypted blobs to it), so there is no
folder name to build a path from. `Collections()` (the Service property) and
every `Collection`/`Item` property getter special-case the sealed state
instead of calling the store at all — see "Fail-closed reads" below.

## Locking — the security-critical contract (go-xkms#723)

The issue this package was filed to fix: **`Lock` and `Unlock` were no-ops**
(any session-bus client could read every secret). The fix:

- **`Lock(objects)`** calls `barrier.Seal()` (idempotent, never errors) and
  reports every named object as now locked. It always locks the whole
  barrier regardless of which objects were named — see architecture.md.
- **`Unlock(objects)`**: if the barrier is already unsealed, returns the
  objects immediately (no prompt). If sealed, creates a `Prompt` and returns
  its path; the objects are returned only via that prompt's `Completed`
  signal, never synchronously — a caller polling the direct return value
  alone can never observe "unlocked" for a sealed barrier.
- **Every method that would touch a secret checks `barrier.IsSealed()`
  first** and fails with `org.freedesktop.Secret.Error.IsLocked`
  (`dbusIsLockedError`) before touching the store: `GetSecrets`,
  `SearchItems` (both Service- and Collection-scoped), `CreateCollection`,
  `SetAlias`, `Collection.Delete`/`CreateItem`, `Item.Delete`/`SetSecret`.
  None of them return a secret, or even attempt to read one, while sealed.

### Prompt resolution and the audit-failure invariant

`Prompt.Prompt(windowID)` calls the daemon's `UnlockFunc`, then
`barrier.Unseal`, then **audits the outcome before declaring success**. A
successful `Unseal` whose audit write then fails is unwound: the barrier is
**re-sealed** and the prompt completes `dismissed`. This is the one place in
the package that goes beyond the "leave prior side effects in place on audit
failure" convention used elsewhere (e.g. `Lock`, where sealing is already
the fail-safe direction) — an unlock that could not be proven to have
happened is exactly the class of bug this issue exists to close. See
`resolveUnlockPrompt`'s doc comment in `prompt.go`.

Every audit write failure for a `SeveritySecurity` operation (create,
delete, unlock, lock, secret read — see `xkey/pkg/audit/severity.go`) fails
the D-Bus call, per go-xkms#688/#765: `logSecretServiceEvent`'s return value
is always propagated as the call's own error. A real `audit.Logger`
implementation applies the informational/security distinction internally
(`audit.handleWriteFailure`); this package trusts whatever it returns.

## FIPS 140

`OpenSession` refuses the `dh-ietf1024-sha256-aes128-cbc-pkcs7` algorithm
whenever `crypto/fips140.Enabled()` is true (`GODEBUG=fips140=only`/`=on`, or
a `GOFIPS140` build), and offers only `plain` in that mode
(`ErrAlgorithmNotFIPSApproved`). This is go-xkms's usual rule — FIPS
enforcement is the Go stdlib's job, never a locally maintained
approved-algorithm list (`xkey/pkg/secretservice/fips.go` mirrors the
pattern already used in `xkey/pkg/oath/fips.go`).

**Why dh-ietf1024 specifically**: the underlying primitives (AES-128-CBC,
SHA-256) are themselves FIPS-approved, but the session key derivation in
`crypto.go` — a raw SHA-256 hash of the DH shared secret, truncated to 16
bytes — is not an approved key-derivation construction (SP 800-56A /
SP 800-135 define the approved ones). Refusing the whole algorithm is
simpler and more conservative than trying to swap in an approved KDF for a
session-transport encryption layer that exists only to protect a secret in
transit across the **local, kernel-mediated D-Bus session bus** — `plain`
carries no meaningfully different exposure on that channel, which is why it
stays available in FIPS mode rather than being refused as well.

## Attributes and search

`ItemAttributesFromPassword` (`mapping.go`) builds the attribute dictionary
a client sees: legacy derived attributes (`service`, `username`, `url`,
`xdg:schema`) from the entry's existing fields, then `StaticPassword.Attributes`
overlaid on top (explicit attributes win on key collision). `SearchItems`
(both the Service-wide and the per-`Collection` form) does an **exact**
dictionary match — no synonym normalization — against that merged set: a
client that wrote `protocol`/`host`/`username` via `CreateItem` (as
`git-credential-libsecret` does) reads those same keys back unchanged.

## Capability interfaces

`aliasStore` (`service.go`) is a local, unexported interface —
`SetAlias(name, folder string) error` / `GetAlias(name string) (string,
bool, error)` — that `Daemon.ReadAlias`/`SetAlias` probe for via a type
assertion on the `xkms.StaticPasswordStore` they were constructed with.
Implemented by `staticpw.BackendStore` (the canonical barrier-backed store
xkey always uses); a `Store` implementation that lacks it (in-memory test
doubles, or the DAO/encrypted/scoped stores quicbaas uses) simply cannot
persist an alias — `SetAlias` still succeeds (it is not an error to lack
optional persistence) but the mapping does not survive a restart, and
`ReadAlias` falls back to `PathMapper.FolderFromAlias`'s built-in
default/login/`CollectionFolderMap` heuristics.

## Errors

All sentinel errors are typed values in `errors.go` — no inline
`errors.New`/`fmt.Errorf` at call sites. Two are mapped onto the Secret
Service API's own D-Bus error names rather than the generic
`org.freedesktop.DBus.Error.Failed`, because libsecret inspects these
specific names to decide whether to retry after a prompt:

| Sentinel(s) | D-Bus error name |
|---|---|
| `ErrCollectionLocked` | `org.freedesktop.Secret.Error.IsLocked` |
| `ErrItemNotFound`, `ErrCollectionNotFound`, `ErrSessionNotFound`, `ErrPromptNotFound` | `org.freedesktop.Secret.Error.NoSuchObject` |

## Known limitations

- **Collection rename is unimplemented.** `Collection.Set("Label", …)`
  always returns `ErrPropertyReadOnly`: renaming a collection means renaming
  its underlying folder, which regenerates the ID (and D-Bus path) of every
  item inside it. Neither of this feature's verification targets
  (`secret-tool`, `git-credential-libsecret`) ever calls it. `Item.Set("Label", …)`
  and `Item.Set("Attributes", …)` ARE implemented (they change only
  `Title`/`Attributes`, never `Name`/`FolderPath`, so the item's path is
  stable).
- **Collection `Created`/`Modified` are derived, not stored**: the min/max
  of its items' own `CreatedAt`/`UpdatedAt` (0 for an empty folder).
  `pkg/staticpw`'s folder marker carries no timestamp of its own.
- **No per-collection lock** — see architecture.md.

## Tests

- `xkey/pkg/secretservice/*_test.go` — unit tests, including a loopback
  in-process D-Bus bus (`newLoopbackBus`/`newBusDaemon` in
  `service_dbus_test.go`) that exercises real object export and signal
  emission without a session bus, a real barrier
  (`newTestBarrier`) for every locked/unlocked-path test, and a
  `failingAuditLogger` double (`audit_failure_test.go`) that exercises the
  audit-failure-fails-the-call and re-seal-on-unauditable-unlock paths.
- `xkey/cmd/xkey/cmd/secret_service_test.go` — password resolution
  precedence and command registration.
- `xkey/test/integration/secretservice_test.go` — `secret-tool`
  store/lookup/clear and `git-credential-libsecret` store/get/erase against
  a live daemon under `dbus-run-session`; run via `make
  integration-test-secretservice` in the devcontainer. As of this writing
  the devcontainer image installs neither `libsecret-tools` nor git's
  libsecret credential helper (see `.devcontainer/Dockerfile`); the test
  fails loudly with that explanation (`requireTool`) rather than skip —
  installing those packages is a separate, owner-approved devcontainer
  change this issue's investigation flagged but did not make.

Run `go test ./pkg/secretservice/...` from `xkey/` with `-tags 'ble
codec_json'` (see the repository's `go.mod`/root `AGENTS.md` for the tag
set); no special hardware or bus is required for the unit suite.
