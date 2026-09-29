# SSH Keys, Known Hosts & Authorized Keys — API

> **Status: NORMATIVE** · Feature: `ssh-keys` · Repo: `go-xkms` · Last verified: 2026-09-28

Transport model: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped". Unlike FROST and the PKCS#11 backend,
this feature needs no build tag and no backend-specific daemon
configuration — see [`architecture.md`](architecture.md). Every route below
is registered on every `xkmsd` build; whether it answers or 501s depends
only on `s.sshHandlers != nil` (the `hasSSH` gate,
`pkg/api/rest/routes.go:453`). `sshHandlers` is built only when the REST
config carries an SSH client (`cfg.SSHClient != nil`,
`pkg/api/rest/server.go:489`).

Permission: each route gates on its own `auth.ResourceSSH` action
(`pkg/api/rest/routes.go:476-503`) — `ssh:read` to read, `ssh:write` to
create, `ssh:delete` to remove, the same pairs the MCP `ssh.*` methods
(`pkg/api/mcp/authz.go:321-341`) and the gRPC `qrdb.v1.permission` options
(`pkg/api/grpc/proto/xkmsv1/xkms.proto:853-915`) carry. Signing is `ssh:write` on
every transport: REST (`pkg/api/rest/routes.go:493`), MCP `ssh.keys.sign`
and gRPC `SSHSign`. Before go-xkms#1230 every REST route, delete and import
included, gated on the single `ssh:use`.

**Owner binding (every transport).** The permission admits the operation,
not the asset: `auth.Authorizer` binds the caller's own tenant as the
target, so it cannot see the `scope`/`owner` a request names. The SSH
service every transport is wired with (`pkg/ssh/tenancy`, built by
`pkg/server/server.go:486-512`) binds them instead
(`pkg/ssh/tenancy/client.go:170-182`):

| Scope | A tenant-scoped caller may address |
|---|---|
| `tenant` | only `owner` = its own tenant ID |
| `user`, `service` | only `owner` = its own subject |

A platform identity (no identity, or the system tenant —
`auth.IsCrossTenant`) may address any owner. A request for an asset the
caller does not own answers exactly as a missing asset does — REST `404`,
gRPC `NotFound`, MCP `JSONRPCCodeNotFound`, with the genuine-miss body
(`pkg/ssh/tenancy/errors.go:44-71`). That includes writes: a `generate`,
`import`, known-hosts `add` or authorized-keys `add` under a foreign owner is
the not-found answer for the address it names, and nothing is written or
generated (`pkg/ssh/tenancy/ops.go:38-59,152-163,237-248`). Listings return
only what the caller owns, whatever `scope`/`owner` filters they carry
(`pkg/ssh/tenancy/ops.go:76-92`).

## REST (`pkg/api/rest/handlers_ssh.go`, base path `/xkms/v1/ssh`)

Note the base path: SSH uses `/xkms/v1/ssh`, not the `/api/v1` prefix the
generic key/FROST routes use (`pkg/api/rest/routes.go:455`).

| Method | Path | Client call | Permission |
|---|---|---|---|
| `POST` | `/keys` | `Keys().Generate` | `ssh:write` |
| `POST` | `/keys/import` | `Keys().Import` | `ssh:write` |
| `GET` | `/keys` | `Keys().List` | `ssh:read` |
| `GET` | `/keys/{scope}/{owner}/{name}` | `Keys().Get` | `ssh:read` |
| `DELETE` | `/keys/{scope}/{owner}/{name}` | `Keys().Delete` | `ssh:delete` |
| `GET` | `/keys/{scope}/{owner}/{name}/public` | `Keys().ExportPublic` | `ssh:read` |
| `POST` | `/keys/{scope}/{owner}/{name}/sign` | `Keys().Signer` (one signature) | `ssh:use` |
| `POST` | `/known-hosts` | `KnownHosts().Add` | `ssh:write` |
| `GET` | `/known-hosts` | `KnownHosts().List` | `ssh:read` |
| `DELETE` | `/known-hosts/{host}` | `KnownHosts().Remove` | `ssh:delete` |
| `POST` | `/known-hosts/{host}/verify` | `KnownHosts().Verify` | `ssh:read` |
| `POST` | `/authorized-keys` | `AuthorizedKeys().Add` | `ssh:write` |
| `GET` | `/authorized-keys` | `AuthorizedKeys().List` | `ssh:read` |
| `GET` | `/authorized-keys/{scope}/{owner}/{name}` | `AuthorizedKeys().Get` | `ssh:read` |
| `DELETE` | `/authorized-keys/{scope}/{owner}/{name}` | `AuthorizedKeys().Remove` | `ssh:delete` |
| `POST` | `/authorized-keys/emit` | `AuthorizedKeys().Emit` | `ssh:read` |
| `POST` | `/authorized-keys/verify` | `AuthorizedKeys().Verify` | `ssh:read` |

The table is pinned by `pkg/api/rest/server_ssh_authz_test.go`: every route
is refused without its grant, admitted with it alone, and refused to a caller
holding every other `ssh:*` action.

### `Key` (response shape for generate/import/get/list)

```jsonc
{"scope": "user", "owner": "alice", "name": "laptop", "algorithm": "ed25519",
 "public_key": "ssh-ed25519 AAAA... laptop", "fingerprint": "SHA256:...",
 "created_at": "2026-09-24T00:00:00Z", "comment": "",
 "backend": "tpm2", "backend_key_id": "ssh-user-alice-laptop"}
```

`backend`/`backend_key_id` are empty for a software-sealed key and set for a
backend-backed one (`sdk/go/client/ssh/types.go:52-62`).

### Sign request body

Both the REST sign route and the MCP `ssh.keys.sign` method take a single
`digest` field (`{"digest": "<base64 bytes>"}`, `[]byte` over JSON): the raw
bytes handed to the resolved `ssh.Signer`'s `Sign` call
(`pkg/api/rest/handlers_ssh.go:483`: "Digest is the raw bytes to sign"; the
MCP handler additionally documents it as "a pre-hashed value; no additional
hashing is performed server-side" — `pkg/api/mcp/handlers_ssh.go:152-154`).
Neither endpoint hashes the input itself; a caller signing a message rather
than a pre-computed digest must hash (or not, matching what `xkmsctl ssh
keys sign --data` does — it passes the raw string through unhashed) before
calling.

### `Pin` (known-hosts)

```jsonc
{"scope": "user", "owner": "alice", "host": "git.example.com",
 "fingerprint": "SHA256:...", "algorithm": "ssh-ed25519",
 "added_at": "2026-09-24T00:00:00Z", "source": "xkmsctl",
 "public_key": "ssh-ed25519 AAAA..."}
```

`public_key` is "required on every pin created via `AddKnownHostRequest` —
the known_hosts store no longer accepts or trusts a fingerprint-only pin"
(`sdk/go/client/ssh/types.go:88-91`).

### `AuthorizedEntry`

```jsonc
{"scope": "user", "owner": "alice", "name": "ci-runner",
 "line": "ssh-ed25519 AAAA... ci-runner",
 "options": ["no-pty"], "comment": ""}
```

## gRPC (`pkg/api/grpc/service_ssh.go`, `proto/xkmsv1/xkms.proto`)

13 RPCs on `KeystoreService`: `SSHGenerateKey`, `SSHImportKey`,
`SSHListKeys`, `SSHGetKey`, `SSHDeleteKey`, `SSHExportPublic`, `SSHSign`,
`SSHAddKnownHost`, `SSHListKnownHosts`, `SSHRemoveKnownHost`,
`SSHAddAuthorizedKey`, `SSHListAuthorizedKeys`, `SSHRemoveAuthorizedKey`.

**No RPC exists for known-hosts `verify` or authorized-keys `emit`/`verify`.**
The gRPC SDK client fills these client-side by calling `List` and comparing
locally — see [`architecture.md`](architecture.md) §"Backend-selection
surface gap". A caller talking gRPC directly (not through `sdk/go/client/ssh`)
must implement the same List-and-compare pattern itself; there is no
server-side verify/emit call to make.

## MCP (`pkg/api/mcp/handlers_ssh.go`, dispatch table in `server.go:415-435`)

Map-dispatched dotted methods, three families:

- `ssh.keys.generate`, `ssh.keys.import`, `ssh.keys.list`, `ssh.keys.get`,
  `ssh.keys.delete`, `ssh.keys.export`, `ssh.keys.sign`
- `ssh.knownHosts.add`, `ssh.knownHosts.list`, `ssh.knownHosts.remove`,
  `ssh.knownHosts.verify`
- `ssh.authorizedKeys.add`, `ssh.authorizedKeys.get`,
  `ssh.authorizedKeys.list`, `ssh.authorizedKeys.remove`,
  `ssh.authorizedKeys.emit`, `ssh.authorizedKeys.verify`

MCP has dedicated handlers for `knownHosts.verify` and
`authorizedKeys.emit`/`verify` — unlike gRPC, these are real server-side
calls (`pkg/api/mcp/handlers_ssh.go:234,328,344`), not client-side
List-and-compare.

`ssh.keys.sign` acquires a `crypto.Signer` for the named key and signs the
caller-supplied data server-side; there is no separate "get signer" MCP
method — signing is one call.

`Session.Dial` (non-interactive outbound command execution) is **not**
exposed over MCP — see [`../ssh-agent-sessions/`](../ssh-agent-sessions/) and
`pkg/api/mcp/handlers_ssh.go:23` ("Session.Dial is not supported over the MCP
transport"). It is out of this folder's scope regardless.

## Go SDK (embedded, no network)

Any Go program can use `pkg/ssh/keys`, `pkg/ssh/known_hosts`,
`pkg/ssh/authorized` directly, or obtain an `sdkssh.Client` via
`sdkssh.NewEmbedded(EmbeddedOptions{Backend: storageBackend, BackendProvider:
provider})` without a running `xkmsd` at all. The embedded client trusts its
caller: it applies no owner binding. A multi-tenant server wraps storage and
backends in `tenancy.New(tenancy.Options{Storage, Resolver})`
(`pkg/ssh/tenancy/client.go:103-116`), exactly as `ensureSSHClient` does
inside the daemon (see architecture.md).
