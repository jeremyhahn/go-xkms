# SSH — API

> **Status: NORMATIVE** · Feature: `ssh` · Module: `go-xkms/xkey` · Last verified: 2026-10-12

No REST/gRPC/QUIC/MCP transport surface belongs to xkey itself — the
network transports for keys/host-keys/authorized-keys/`Session.Dial` are
served by xkmsd and documented at
[`../../../docs/ssh-keys/api.md`](../../../docs/ssh-keys/api.md). This
document covers what is reachable only through xkey: the GUI's Wails
bindings, and the loopback WebSocket bridge the embedded console uses.

## GUI bindings

All types below are JSON-tagged for the Wails bridge; see each service's
source file for exact field lists.

### `SSHService` (`ssh_service.go`) — keys and backend selection

| Capability | Method |
|---|---|
| Generate a key | `GenerateKey(params SSHGenerateParams) (*SSHKeyInfo, error)` |
| List keys | `ListKeys() ([]*SSHKeyInfo, error)` |
| Get one key | `GetKey(name string) (*SSHKeyInfo, error)` |
| Export the public half | `ExportPublic(name string) (string, error)` |
| Delete a key | `DeleteKey(name string) error` |
| List SSH-capable backends | `ListBackends() ([]SSHBackendInfo, error)` |
| Get/set the default backend | `GetDefaultBackend() string` / `SetDefaultBackend(backendID string) error` |
| Algorithms a backend supports | `SupportedAlgorithms(backendID string) []string` |
| Wiring (not Wails-bound) | `SetContext`, `SetEmbeddedClient`, `SetRemoteClientFunc`, `SetRegistry`, `SetAuditLogger`, `SetLogger` |

Keys are always scoped `user`/`local` from the GUI (`sshDefaultScope`,
`sshDefaultOwner`) — the CLI exposes the full scope/owner surface for
multi-tenant use; the GUI operates a single local custodian.
`SupportedAlgorithms` derives its answer from the backend's registered
category (software/tpm2/pkcs11/phone) via the SDK's
`sshclient.SupportedAlgorithms` — the same mapping the CLI's `--type`
validation implicitly relies on — so, for example, a `tpm2` backend never
offers `ed25519` (TPM 2.0 has no native Ed25519 key object type).

### `SSHProfileService` (`ssh_profile_service.go`) — connection profiles

| Capability | Method |
|---|---|
| List / list by folder | `ListProfiles() ([]SSHProfileEntry, error)` / `ListProfilesByFolder(folderPath string) ([]SSHProfileEntry, error)` |
| List folders | `ListFolders() ([]string, error)` |
| Get one | `GetProfile(idOrName string) (*SSHProfileEntry, error)` |
| Add / update | `AddProfile(params SSHProfileParams) (*SSHProfileEntry, error)` / `UpdateProfile(params SSHProfileParams) error` |
| Delete | `DeleteProfile(idOrName string) error` |
| Move to a folder | `MoveProfile(idOrName, folderPath string) error` |
| Folder management | `CreateFolder(path string) error`, `RenameFolder(oldPath, newPath string) error`, `DeleteFolder(path string) error` |
| Search | `SearchProfiles(query string) ([]SSHProfileEntry, error)` |
| Wiring | `SetContext`, `SetStore`, `Store()` |

### `SSHConnectService` (`ssh_connect_service.go`) — system-terminal launch

| Capability | Method |
|---|---|
| Connect a saved profile | `ConnectProfile(profileID string) error` |
| Connect a one-time target | `ConnectOneTime(params SSHConnectParams) error` |
| Connect via an `ssh_config` alias | `ConnectConfigHost(alias string) error` |
| Stop every live session | `StopAll()` |
| Policy setters | `SetKnownHostsPolicy(policy string)`, `SetStrictHostKeyChecking(policy string)`, `SetTerminalCommand(cmd string)` |
| Wiring | `SetContext`, `SetSSHClient`, `SetHostKeyStore`, `SetProfileService`, `SetLogger` |

`ConnectProfile`/`ConnectOneTime`/`ConnectConfigHost` all funnel through
`launch` (xkey-managed key, in-process agent) or `launchPassthrough`
(local/no-key) depending on the resolved `KeySource` — see
[architecture.md](architecture.md#shape-chosen-three-ways-to-reach-a-host-chosen-by-key-source).
A launched session is tracked (`register`/`watch`) so `StopAll` (called on
app shutdown) can terminate every outstanding `ssh` process.

### `SSHConsoleService` (`ssh_console_service.go`) — embedded console

| Capability | Method |
|---|---|
| Open a console (profile / one-time / config host) | `OpenProfileConsole(profileID string) (*SSHConsoleEndpoint, error)`, `OpenConsole(params SSHConnectParams) (*SSHConsoleEndpoint, error)`, `OpenConfigHostConsole(alias string) (*SSHConsoleEndpoint, error)` |
| Persistent sessions | `SaveSession(rec sshclient.ConsoleSessionRecord) (*sshclient.ConsoleSessionRecord, error)`, `ListSessions() ([]*sshclient.ConsoleSessionRecord, error)`, `DeleteSession(id string) error` |
| Policy setters | `SetHostKeyPolicy(policy string)`, `SetKnownHostsPolicy(policy string)` |
| Shutdown | `Shutdown()` |
| Wiring | `SetContext`, `SetSSHClient`, `SetHostKeyStore`, `SetProfileService`, `SetSessionStore`, `SetLogger` |

`Open*` returns an `SSHConsoleEndpoint{URL, Token}`: `URL` is a
`ws://127.0.0.1:<port>/console?token=<token>` address on a lazily-started
loopback server (`ensureServer`), and `Token` is single-use — the
frontend's xterm.js client (wrapping `sshclient.NewConsoleWSHandler`, root
SDK) dials it to open the actual PTY stream. The signer(s) for the
connection are resolved *before* the endpoint is returned
(`open`/`resolveLocalParams`), so a bad key reference surfaces as a GUI
dialog error rather than a WebSocket handshake failure. An issued-but-
never-connected ticket is purged after 2 minutes
(`consoleTicketTTL`). See [`../../../docs/ssh-sessions/engineering.md`](../../../docs/ssh-sessions/engineering.md#websocket-wire-protocol) for the WebSocket wire protocol
(binary terminal frames, JSON control frames, host-key confirmation
round trip).

### `SSHLocalService` (`ssh_local_service.go`) — read-only local discovery

| Capability | Method |
|---|---|
| List `ssh_config(5)` hosts | `ListConfigHosts() ([]SSHConfigHostEntry, error)` |
| List local agent/`~/.ssh` keys | `ListLocalKeys() ([]SSHLocalKeyInfo, error)` |

A thin pass-through to `xkey/pkg/sshlocal` — see
[engineering.md](engineering.md#package-xkeypkgsshlocal).

## `xkey/pkg/sshstore` and `xkey/pkg/sshlocal`

Not Wails-bound — plain Go packages called by both the CLI and the GUI's
service constructors. See
[engineering.md](engineering.md#exported-surface) for their exported
functions; there is no separate "API" for them beyond that Go surface.

## See also

- [Architecture](architecture.md) — why the console is a loopback
  WebSocket server rather than a direct Wails call
- [Engineering](engineering.md) — exported surface, invariants, tests
- [CLI](cli.md) — the CLI's equivalent surface
- Root SSH transports (REST/gRPC/QUIC/MCP/unix, `Session.Dial`, the
  console wire protocol): [`../../../docs/ssh-keys/api.md`](../../../docs/ssh-keys/api.md),
  [`../../../docs/ssh-sessions/api.md`](../../../docs/ssh-sessions/api.md)
