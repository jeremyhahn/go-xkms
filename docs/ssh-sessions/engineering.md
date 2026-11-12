# SSH Connect & Console Sessions — Engineering

> **Status: NORMATIVE** · Feature: `ssh-sessions` · Repo: `go-xkms` · Last verified: 2026-10-12

## Exported surface

### `pkg/ssh/console`

- `Dial(ctx, DialRequest, Config) (Console, error)` (`console.go:162`) —
  dials a host and opens an interactive PTY. `DialRequest`
  (`console.go:118`) carries a pre-resolved `ssh.Signer` (or `Signers`,
  offered in order like an OpenSSH agent), `KnownHosts`, and an optional
  `HostKeyConfirm` TOFU callback; `Config` (`console.go:84`) carries
  `Term`/`Rows`/`Cols`/`Env`, each with a zero-value default
  (`defaultTerm`/`defaultRows`/`defaultCols`).
- `Open(client *ssh.Client, cfg Config) (Console, error)` (`console.go:306`)
  — the lower-level entry point for a caller that already has a dialed
  `*golang.org/x/crypto/ssh.Client`.
- `Console` interface (`console.go:71`): `Read`/`Write` (terminal I/O),
  `Resize(rows, cols int) error`, `CloseWrite() error`, `Close() error`.
- `NewWSHandler(resolver Resolver, opts ...HandlerOption) http.Handler`
  (`handler.go:146`) — the WebSocket↔SSH bridge. `Resolver`
  (`handler.go:77`) resolves an `http.Request` to a `Target`
  (`handler.go:36`, carrying host/port/user/scope/owner plus a signer and
  a known-hosts store); `ResolverFunc` (`handler.go:82`) adapts a plain
  function. Options: `WithCheckOrigin`, `WithDialTimeout`,
  `WithHostKeyConfirmTimeout` (`handler.go:125,130,138`).

#### WebSocket wire protocol

Binary frames carry terminal bytes in both directions: client input goes to
the session (`handler.go:390`) and session output goes back to the client
(`:348`). Text frames carry a JSON `controlMessage` whose `type` is
`"resize"`, `"error"` or `"exit"` (`handler.go:92`). The client sends
`{"type":"resize","rows":R,"cols":C}` (`:396`). The server sends `"error"`
when the dial fails (`:224`) and `"exit"` when the session output ends
(`:355`). When the client's input ends, the bridge calls `CloseWrite` before
it tears the session down (`:418`).

#### Host-key policy on the WebSocket bridge

`Target.HostKeyPolicy` selects how the bridge treats an unpinned host key
(`handler.go:242-277`):

| Policy | Behavior |
|---|---|
| `"ask"` | Sends a `"hostkey"` frame with `mode: "confirm"`, then blocks for the client's `{"type":"hostkey-response","accept":…}` reply (`handler.go:243-256`, `awaitHostKeyResponse` `:287`). The wait is bounded by `defaultHostKeyConfirmTimeout`, 60s (`handler.go:173`), overridable with `WithHostKeyConfirmTimeout` (`handler.go:139`). |
| `"accept-new"` | Sends a `"hostkey"` frame with `mode: "notify"` and accepts without waiting; a failed notify write is logged, not fatal (`handler.go:258-274`). |
| anything else, including `""` and `"yes"` | Strict: no prompt, the dial fails on an unpinned host (`handler.go:276`). |

The `"hostkey"` frame carries `host`, `key_type`, `fingerprint`, `known`
and `mode` (`hostKeyMessage`, `handler.go:104-111`). A pin that conflicts
with the presented key is always a hard `*known_hosts.MismatchError`; TOFU
never overrides it, whatever the policy (`console.go:200`, `:241`). The SDK's
`ConsoleTarget` adds `KnownHostsExtraFiles` (extra OpenSSH `known_hosts`
files) and `KnownHostsSkipStore` (skip the pin store and use only those
files) (`sdk/go/client/ssh/console.go:62-70`), and passes all three fields
through (`:131-133`).

### `pkg/ssh/session`

- `Dial(ctx, DialRequest) (Session, error)` (`dial.go:102`) — a
  non-interactive session for `Run`/file transfer. `DialRequest`
  (`dial.go:36`) takes ownership of a `*keys.Key` on success — "callers
  must NOT Destroy the Key after a successful Dial; callers MUST Destroy
  it themselves on Dial failure" (`dial.go:31-35`).
- `DialClient(ctx, ClientParams) (*ssh.Client, error)` (`dial.go:163`) —
  the lower-level dial used when the caller wants the raw
  `*golang.org/x/crypto/ssh.Client` instead of a `Session`.

### `pkg/ssh/connect`

- `Start(ctx, Request) (*Session, error)` (`connect.go:177`) — launches
  the in-process signing agent, seeds a temporary `known_hosts`, and
  returns the argv/env for the caller to exec the system `ssh` binary
  with. `Request` (`connect.go:41`) carries the target, a pre-resolved
  `ssh.Signer`, a `known_hosts.Store`, and knob fields
  (`ExtraOptions`, `StrictHostKeyChecking`, `ExtraKnownHosts`,
  `SkipStore`, `WorkDir`).
- `(*Session) Sync(ctx) (int, error)` (`connect.go:309`) — merges
  newly-accepted host keys from the temp file back into the store,
  returning the count merged.
- `(*Session) Stop(ctx) sshagent.ShutdownReport` (`connect.go:398`) and
  `SyncAndStop(ctx) (int, sshagent.ShutdownReport, error)`
  (`connect.go:514`) — tear down the agent; `Err()` (`connect.go:487`)
  and `KnownHostsFile()` (`connect.go:567`) round out the handle.

### `pkg/ssh/sessions`

- `Session` struct (`types.go:25`): `ID`, `Title`, exactly one origin
  group (`Host`/`Port`/`User`/`Key*`/`LocalIdentity`, or `ProfileID`, or
  `Alias`), `CreatedAt`/`LastConnectedAt`. `Validate()` (`types.go:57`)
  enforces the "exactly one origin" invariant.
- `Store` interface (`store.go:35`): `Save`, `Get(id)`, `List()`,
  `Delete(id)`, `Close()`. `NewStore(daos *qrdbsdk.DAOFactory)
  (*DAOStore, error)` (`store.go:69`) is the only implementation: each
  session is a go-qrdb DAO entity in the `ssh` database (nil `daos` →
  `ErrNilDAOFactory`).

### `pkg/ssh/profile`

- `Profile` struct (`types.go:33`): `ID` (deterministic, from `Name` +
  `FolderPath` via `GenerateID`, `types.go:121`), `Name`, `FolderPath`,
  `Host`/`Port`/`User`, `KeyScope`/`KeyOwner`/`KeyName`, `KeySource`
  (`""` for an xkey-managed key, `"local"` for
  `pkg/ssh/local`-resolved), `SSHConfigAlias`.
- `Store` interface (`store.go:43`): CRUD (`Add`/`Get`/`List`/`Update`/
  `Delete`) plus folder operations
  (`ListByFolder`/`ListByFolderDirect`/`ListFolders`/`MoveToFolder`/
  `CreateFolder`/`RemoveFolder`/`RenameFolder`/`DeleteFolder`) and
  `Search(query)`. `NewStore(daos *qrdbsdk.DAOFactory) (*DAOStore,
  error)` (`store.go:109`) is the only implementation: profiles and
  folders are go-qrdb DAO entities in the `ssh` database (nil `daos` →
  `ErrNilDAOFactory`).

### Migrating the pre-DAO stores

`sessions.DAOStore.ImportLegacy(ctx, id, data)` (`pkg/ssh/sessions/store.go:164`),
`profile.DAOStore.ImportLegacy(ctx, id, data)` (`pkg/ssh/profile/store.go:427`)
and `profile.DAOStore.ImportLegacyFolder(ctx, path)`
(`pkg/ssh/profile/store.go:452`) import one record of the old sealed-KV
layout (`ssh/sessions/<id>`, `ssh/profiles/<id>.json`,
`ssh/profiles/__folders__/<path>`). They keep the old ID, upsert, and wrap a
corrupt or invalid record in `ErrLegacyRecord`. `pkg/ssh/migrate.Run`, exported
as `sdk/go/client/ssh.MigrateLegacyStores`, drives them and deletes each old
key only after its import succeeds; tenant-prefixed sessions and profiles are
skipped and left in place. The full contract is in
`../ssh-keys/engineering.md` §"Exported surface — `pkg/ssh/migrate`".

### `pkg/ssh/local`

- `LoadConfig(paths ...string) (*Config, error)` and
  `DefaultConfigPaths() []string` (`config.go:79,114`) — parses the
  `ssh_config(5)` chain. `(*Config) Lookup(alias)`/`LookupStrict(alias)`
  (`config.go:130,167`) resolve a `HostConfig` (`config.go:33`) by alias;
  `Aliases()` (`config.go:189`) lists configured hosts.
- `DialAgent(sockPath string) ([]ssh.Signer, error)` and
  `SignerForPublicKey(sockPath string, pub ssh.PublicKey) (ssh.Signer,
  error)` (`agent.go:45,74`) — reads keys from a running `ssh-agent`.
- `ResolveSigner(ctx, identity *Identity, authSockPath string)
  (ssh.Signer, error)` (`signer.go:61`) — resolves a signer for one
  discovered identity, trying the agent first.

### `sdk/go/client/ssh` (the SDK-facing surface these packages compose into)

- `Client.Console(ctx, ConsoleConnectRequest, ConsoleConfig)
  (ConsoleSession, error)` — `ConsoleConnectRequest`
  (`client.go:56`) selects the key (`KeyScope`/`KeyOwner`/`KeyName`) and
  target (`Host`/`Port`/`User`); `ConsoleConfig` is a type alias for
  `pkg/ssh/console.Config` (`console.go:33`); `ConsoleSession` is a type
  alias for `pkg/ssh/console.Console` (`console.go:27`).
- `Client.Session() SessionClient`, with `SessionClient.Dial(ctx,
  SessionDialRequest) (Session, error)` implemented per transport
  (`embedded.go:544`, `rest.go:581`, `grpc.go:412`, `mcp.go:613`) —
  `restSessionClient.Dial` and `grpcSessionClient.Dial`/`mcpSessionClient.Dial`
  all funnel through the shared `dialNetworkSession` helper, composing
  the transport's own `KeysClient`/`KnownHostsClient` rather than adding
  a new route.
- `StartConnect(ctx, ConnectOptions) (*ConnectSession, error)`
  (`connect.go:69`) is the SDK-level entry point for
  `pkg/ssh/connect.Start`: `ConnectOptions` (`connect.go:42`) takes a
  string `Scope` ("tenant"/"user"/"service") and a `Signer` resolved from
  `Client.Keys().Signer`; `ConnectSession` is a type alias for
  `pkg/ssh/connect.Session` (`connect.go:31`).
- `NewConsoleWSHandler(resolver ConsoleResolver, opts
  ...pkgconsole.HandlerOption) http.Handler` (`console.go:108`) — the SDK
  re-export of `pkg/ssh/console.NewWSHandler`, documented in
  [`architecture.md`](architecture.md).
- `NewProfileStore(daos *qrdbsdk.DAOFactory) (ProfileStore, error)`
  (`profile.go:33`) and `NewConsoleSessionStore(daos *qrdbsdk.DAOFactory)
  (ConsoleSessionStore, error)` (`sessions.go:33`) are thin re-exports of
  `pkg/ssh/profile.NewStore` and `pkg/ssh/sessions.NewStore` — "so SDK
  consumers (the xkey GUI/CLI) never import `pkg/ssh/profile` directly"
  (`profile.go:21-22`). `NewHostKeyStore(daos *qrdbsdk.DAOFactory)
  (HostKeyStore, error)` (`connect.go:36`) is the equivalent for
  `known_hosts.Store`. Each file also re-exports the package's error
  sentinels under an SDK-prefixed name (e.g. `ErrProfileNotFound`,
  `ErrConsoleSessionInvalidOrigin`, `profile.go:39-46`,
  `sessions.go:38-42`) for `errors.Is` checks without importing the
  underlying package.

## Invariants

- **The signer never leaves the process that holds it.** Every entry
  point in this folder takes a pre-resolved `ssh.Signer` (or, for
  `session.Dial`, a `*keys.Key` it takes ownership of) — none of these
  packages accept or transmit raw private key material.
- **No trust-on-first-use by default.** `session.DialRequest.KnownHostsStore`
  and `console.DialRequest.KnownHosts` are required fields; an unpinned
  host fails the handshake unless the caller explicitly supplies a
  `HostKeyConfirm` callback (`console`) — there is no implicit-accept
  path.
- **Exactly one `sessions.Session` origin.** `Validate()` rejects a
  record with zero or more than one of the raw-tuple/`ProfileID`/`Alias`
  origin groups set.
- **`pkg/ssh/local` never writes.** Every exported function only reads
  `ssh_config(5)` files, default identity files, and a running agent
  socket; the package doc comment states this as a hard boundary
  (`pkg/ssh/local/doc.go`).
- **`connect.Session` key ownership follows the same success/failure
  split as `session.Dial`.** A successful `Start` hands the caller a
  `Session` that owns the agent's lifetime; `Stop`/`SyncAndStop` are the
  only teardown path.

## Errors

Every package in this folder uses typed errors (never a bare
`fmt.Errorf`), following the project-wide convention:

| Package | Types |
|---|---|
| `console` | `InputError` (`errors.go:17`) |
| `connect` | `InputError`, `LaunchError` (`errors.go:17,24`) |
| `session` | `NilInputError`, `DialError`, `HandshakeError`, `TimeoutError`, `CommandError`, `SessionError`, `UploadError`, `UnsafePathError` (`errors.go:20-134`) |
| `local` | `NilInputError`, `ConfigParseError`, `AgentUnavailableError`, `AgentKeyNotFoundError`, `IdentityReadError`, `HostNotConfiguredError` (`errors.go:27-106`) |
| `sdk/go/client/ssh` | `ConsoleUnsupportedError{Transport string}` (`errors.go:66`) — returned by every non-embedded `Client.Console` |

`ConsoleUnsupportedError.Error()` reads "...(use embedded/gRPC, or the
WebSocket bridge for REST/QUIC)" (`errors.go:71-73`), but this is
misleading for gRPC: `grpcClient.Console` (`grpc.go:111`) returns the
same error unconditionally — gRPC does not support `Console` either. The
only paths that ever construct a working `ConsoleSession` are the
embedded client (`embedded.go:108`) and the WebSocket bridge
(`NewConsoleWSHandler`), consumed today only by xkey's desktop GUI. Fixing
the message (or gating it on `Transport`) is a documentation-only
follow-up; no behavior needs to change.

## Configuration

None of these packages read daemon configuration (`xkmsd`'s config or
`XKMS_*` environment) — every input arrives as a Go struct field
(`DialRequest`, `Request`, `ConsoleConnectRequest`) from the calling
process. There is no `config.yaml` key, flag, or environment variable
specific to console/connect/session/profile/local in this repository.

## Transport surface (none, by design)

Grepping the server-side transports confirms no route exists for any
capability in this folder:

- REST: `pkg/api/rest/routes.go`'s `ssh(...)` helper (`routes.go:454`)
  registers only `/keys`, `/known-hosts`, and `/authorized-keys` variants
  — no `/connect`, `/console`, `/session`, `/profile`, or `/sessions`
  pattern.
- gRPC: `pkg/api/grpc/service_ssh.go` defines no `Console`/`Connect`/
  `Dial` RPC; `grpcClient.Console` is the two-line refusal at
  `grpc.go:111`.
- MCP: `pkg/api/mcp/server.go`'s `rpcMethods` table
  (`server.go:499-517`, mirrored by `authz_test.go:720-736`) lists only
  `ssh.keys.*`, `ssh.knownHosts.*`, `ssh.authorizedKeys.*` tools.

See [`architecture.md`](architecture.md) for why `SessionClient.Dial`
still works over every transport despite this — it composes the
`ssh-keys` endpoints rather than needing a route of its own.

## Test strategy

- `pkg/ssh/console`: `console_test.go`, `console_gaps_test.go`,
  `console_known_hosts_test.go`, `console_lifecycle_test.go`,
  `console_session_test.go`, `handler_test.go`, `handler_gaps_test.go`,
  `handler_hostkey_test.go`, `fips_helpers_test.go`.
- `pkg/ssh/connect`: `connect_test.go`, `connect_gaps_test.go`.
- `pkg/ssh/session`: `session_test.go`, `session_extra_test.go`,
  `session_upload_test.go`, `dial_gaps_test.go`, `config_test.go`,
  `config_gaps_test.go`, `fips_helpers_test.go`.
- `pkg/ssh/sessions`: `store_test.go`.
- `pkg/ssh/local`: `config_test.go`, `agent_test.go`, `identity_test.go`,
  `signer_test.go`, `tokens_test.go`.
- `pkg/ssh/profile`: `store_test.go`, `store_gaps_test.go`.
- SDK-level: `sdk/go/client/ssh/grpc_test.go` and `mcp_test.go` each assert
  `Console` returns `*ConsoleUnsupportedError` for their transport;
  `dial_schemes_test.go` covers the REST/QUIC case.
  `embedded_console_test.go` exercises the real `Console` path (embedded
  is the one transport that implements it).

No build tag gates any package in this folder — every `xkmsd`/`xkey`
binary compiles them in, the same way `ssh-keys/architecture.md`
documents for `pkg/ssh/keys`.
