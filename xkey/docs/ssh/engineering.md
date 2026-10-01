# SSH — Engineering Contract

> **Status: NORMATIVE** · Feature: `ssh` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Exported surface

### Package `xkey/pkg/sshstore`

Single construction point for the shared SSH storage backend (package doc
comment, `store.go`). Must not import `xkey/pkg/gui` — it sits below both
front ends.

- `ResolveBackend(dataDir string, engineKind xkmssdk.StorageEngineKind,
  barrierBackend xkmssdk.StorageBackend) (xkmssdk.StorageBackend, error)`
  — barrier-routed when `barrierBackend != nil` (prefix `"ssh/"`);
  otherwise a plain engine store at `<dataDir>/ssh` (`dataDir` required in
  this mode).
- `MissingDataDirError` — returned when `barrierBackend == nil` and
  `dataDir == ""`.

### Package `xkey/pkg/sshlocal`

Read-only local `ssh_config(5)`/agent/`~/.ssh` discovery, shared by the
CLI and GUI (package doc comment, `hosts.go`). Never imports `go-xkms/pkg`
directly — only the SDK.

- `ListConfigHosts() ([]ConfigHostEntry, error)` — every literal `Host`
  alias from `~/.ssh/config` + `/etc/ssh/ssh_config`, fully resolved. A
  missing config file is not an error.
- `ListLocalKeys() ([]LocalKeyInfo, error)` — every key visible via the
  system agent (`$SSH_AUTH_SOCK`) plus `~/.ssh` identity files not already
  represented by an agent entry, deduplicated by fingerprint. A missing
  agent or `~/.ssh` is not an error.
- `ConfigHostEntry{Alias, Hostname, User, Port, IdentityFiles}`,
  `LocalKeyInfo{Source, Path, KeyType, Fingerprint, Comment}` (`Source` is
  `SourceAgent` or `SourceFile`).
- `ConfigLoadError{Err}`, `IdentityDiscoveryError{Err}`.

### Package `xkey/pkg/gui/services` (SSH surface)

- `SSHService` — key generation/list/get/export/delete and backend
  selection. `NewSSHService(embedded sshclient.Client) *SSHService`.
  Types: `SSHKeyInfo`, `SSHGenerateParams`, `SSHBackendInfo`. Errors (in
  `xkey/pkg/gui/services/errors.go`): `ErrSSHUnavailable`,
  `ErrSSHMissingName`. See [api.md](api.md) for the full method table.
- `SSHProfileService` — folder-organized connection profiles.
  `NewSSHProfileService(store sshclient.ProfileStore) *SSHProfileService`.
  Types: `SSHProfileEntry`, `SSHProfileParams`. Error:
  `ErrSSHProfileStoreNotSet`.
- `SSHConnectService` — launches `ssh` in the system terminal.
  `NewSSHConnectService() *SSHConnectService`. Types: `SSHConnectParams`.
  Errors: `ErrSSHConnectNotConfigured`, `ErrSSHConnectNoTerminal`,
  `ErrSSHConnectUnsupportedPlatform`, `ErrSSHConnectProfileNotFound`,
  `ErrSSHConnectMissingTarget`.
- `SSHConsoleService` — loopback WebSocket bridge for the embedded
  console. `NewSSHConsoleService() *SSHConsoleService`. Types:
  `SSHConsoleEndpoint`, `LocalIdentityAttemptError` (alias of
  `sshclient.LocalIdentityAttemptError`), `NoUsableLocalIdentityError`
  (alias of `sshclient.NoUsableLocalIdentityError`). Errors:
  `ErrSSHConsoleNotConfigured`, `ErrSSHConsoleProfileNotFound`,
  `ErrSSHConsoleMissingAlias`, `ErrSSHConsoleInvalidToken`,
  `ErrSSHConsoleSessionStoreNotSet`.
- `SSHLocalService` — thin Wails wrapper over `xkey/pkg/sshlocal`.
  `NewSSHLocalService() *SSHLocalService`. Types: `SSHConfigHostEntry`,
  `SSHLocalKeyInfo`.

### Package `xkey/cmd/xkey/cmd` (SSH surface)

`SSHCmd` (`Use: "ssh"`) and its subtree (`ssh.go`, `ssh_connect.go`,
`ssh_console_cmd.go`, `ssh_local.go`, `ssh_sessions.go`) — see
[cli.md](cli.md) for every verb and flag. Typed errors:
`ErrSSHMissingKeyName`, `ErrSSHMissingImportFile`,
`ErrSSHInvalidKeyType`, `ErrSSHMissingHost`, `ErrSSHMissingHostKey`,
`ErrSSHReadHostKeyFile`, `ErrSSHParseHostKey`, `ErrSSHClientConstruct`,
`ErrSSHStoreBarrierEncrypted`, `ErrSSHConnectTarget`,
`ErrSSHProfileAddRequired`, `ErrSSHProfileMoveFolder`, and
`SSHConfigError{Op, Err}`.

## Invariants

- `sshstore.ResolveBackend` never migrates data between the
  barrier-routed and plain-engine forms — see
  [architecture.md](architecture.md#shape-chosen-one-shared-storage-resolver-routed-by-barrier-state).
- The CLI never attempts to unlock a barrier-encrypted SSH store; it fails
  with `ErrSSHStoreBarrierEncrypted` before any store operation is
  attempted (`xkeySSHBackend`, `ssh.go`).
- `sshHostPublicKeyFromFlags` (`ssh.go`) requires the **full** host public
  key (`--key` or `--file`) — `ErrSSHMissingHostKey` when neither is set.
  A pin can no longer be created from a fingerprint alone.
- `buildLocalSSHArgs` / `SSHConnectService.launchPassthrough` never add
  `-o`/known-hosts/agent-socket options — the defining property of "local
  passthrough" is that xkey adds nothing to the `ssh` invocation beyond
  `-p`/`-i`/the target.
- `resolveSSHConnect` / `runSSHConsole` set `Local = true` whenever
  `--identity` or `--ssh-config-alias` is non-empty, and whenever no key
  name is resolved (from flags or profile) — a key-less invocation always
  falls through to local/passthrough rather than erroring.
- `SSHConsoleService`'s issued tickets are **single-use**: `resolve`
  deletes the ticket from its map on first lookup, and unclaimed tickets
  are purged after `consoleTicketTTL` (2 minutes).
- `SSHConsoleService.hostKeyPolicy` and `SSHConnectService.strictPolicy`
  both default to `"ask"`; `knownHostsPolicy` on both defaults to
  `"barrier"` — chosen so a fresh install's first connection raises a
  fingerprint prompt instead of hard-failing against an empty pin store.
  See root docs for the full TOFU policy semantics.

## Configuration

| Source | Key / variable | Read by |
|---|---|---|
| Environment | `XKMSD_URL`, `XKEY_XKMSD_URL` | `sshClient` (CLI) via `resolveXKMSdEndpoint` — selects the server (any scheme) when `--server` is unset and `--local` is not given |
| Environment | `XKMSD_TOKEN` | `sshClient` (CLI) via `resolveXKMSdToken` — bearer token on every transport; when unset, the login `xkey auth login` stored for the server URL |
| Environment | `XKMSD_TLS_CA`, `XKMSD_TLS_CERT`, `XKMSD_TLS_KEY` | `sshClient` (CLI) — server trust and mTLS client credential on TLS transports |
| Config file | `xkmsd_url` (viper), `xkmsd.address` | `sshClient` (CLI) — same effect as `XKMSD_URL`, lower precedence |
| Config file | `State.StorageEngine` (`xkey/pkg/config`) | `xkeySSHStorageEngineKind` — selects `file`/`pebble`/`memory` for the plain-engine store; defaults to `file` |
| Environment | `SSH_AUTH_SOCK` | `sshlocal.ListLocalKeys`, `ResolveLocalSigners` (via the SDK) — system agent socket |
| Environment | `TERM` | `runSSHConsole` (CLI) — terminal type sent to the remote PTY; falls back to `xterm-256color` |
| Environment | `USER`, `LOGNAME` | `defaultOwner` (CLI) — default `--owner` when unset |

There is no `ssh:` section in the xkey config file — every other setting
(`--known-hosts-policy`, `--key-source`, host-key/known-hosts store
policy) is a CLI flag, or, on the GUI, an in-memory `SSHConnectService`/
`SSHConsoleService` setter (`SetKnownHostsPolicy`, `SetHostKeyPolicy`,
`SetStrictHostKeyChecking`, `SetTerminalCommand`) with no
`xkey/pkg/config`-backed persistence: `xkey/pkg/gui/app.go` never calls
any of them at startup, so whatever the Settings → SSH page does to
restore a choice across restarts happens entirely on the frontend side,
outside this module's Go surface.

## Known gaps

- **The CLI cannot unlock a barrier-encrypted SSH store.** See
  [architecture.md](architecture.md#shape-chosen-the-cli-has-no-unlock-flow-and-fails-closed).
- **Local, encrypted PEM import is CLI/embedded-only.** Root docs note
  encrypted PEM import over remote transports is not supported (no
  passphrase channel); the xkey CLI's `ssh keys import` reads the
  passphrase via `sshPassphraseProvider` (terminal, no echo, or stdin) but
  this only works against the embedded transport, not a `--server`
  target.

## Tests

- `xkey/pkg/sshstore/store_test.go` — `ResolveBackend` (barrier-routed,
  plain-engine, missing-data-dir error).
- `xkey/pkg/sshlocal/hosts_test.go`, `keys_test.go` — config-host
  resolution and local-key discovery/dedup, including the
  missing-config/missing-agent non-error paths.
- `xkey/pkg/gui/services/ssh_service_test.go`,
  `ssh_profile_service_test.go`, `ssh_local_service_test.go` — key
  CRUD/backend selection, profile CRUD/folder operations, and local
  discovery pass-through.
- `xkey/pkg/gui/services/ssh_connect_service_test.go` — profile/one-time/
  config-host connect launch paths, terminal resolution, and session
  bookkeeping (register/watch/`StopAll`).
- `xkey/pkg/gui/services/ssh_console_service_test.go` — ticket issuance,
  policy defaults, session save/list/delete, and token resolution.
- `xkey/pkg/gui/services/ssh_console_e2e_test.go` — a fresh
  `SSHConsoleService` (default policies, empty pin store) driven through a
  real WebSocket client and an in-process SSH server, added after a unit
  test that pre-pinned the host missed a first-contact regression on a
  fresh install.
- `xkey/cmd/xkey/cmd/ssh_cmds_test.go` — every `keys`/`host-keys`/
  `authorized-keys` verb, success and error cases.
- `xkey/cmd/xkey/cmd/ssh_connect_test.go` — `resolveSSHConnect` /
  `buildLocalSSHArgs` resolution logic (profile merge, `--local`
  inference, target parsing).
- `xkey/cmd/xkey/cmd/ssh_local_test.go` — `ssh local hosts`/`keys` output.
- `xkey/cmd/xkey/cmd/ssh_store_test.go` — `xkeySSHBackend` /
  `resolveXKeySSHDataDir` resolution, including the
  barrier-encrypted-store rejection.

## See also

- [Architecture](architecture.md) — why the storage/transport/local-key
  layers are shared this way
- [CLI](cli.md) — every `xkey ssh` verb and flag
- [API](api.md) — GUI bindings and the two shared packages
