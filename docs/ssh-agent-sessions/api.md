# SSH Agent Sessions — API

> **Status: NORMATIVE** · Feature: `ssh-agent-sessions` · Repo: `go-xkms` · Last verified: 2026-09-06

## Transport coverage

**In-process only, by design — not a gap.**

| Transport | Carries this feature | Why |
|---|---|---|
| embedded | **yes** | `StartAgent` is a package-level SDK function, like `StartConnect` |
| rest | n/a | see below |
| grpc | n/a | see below |
| quic | n/a | see below |
| unix | n/a | see below |
| mcp | n/a | see below |
| usb | n/a | see below |

An agent-only session is a **unix socket in the caller's own process**, created
so a child process of that caller can reach a signer. Serving it from a remote
xkms would mean either exporting the private key to the caller — the one thing
the whole design exists to prevent — or exposing a signing oracle on the
network. Neither is a transport implementation of this feature; both are
different, worse features.

This is why `StartAgent` is a package-level function rather than a method on
`Client`: the multi-transport completeness rule applies to the `Client`
interface, and this surface deliberately sits beside it, exactly as
`StartConnect` and `NewHostKeyStore` already do.

**Remote keys still work.** The transport question is about where the *socket*
lives, not where the *key* lives. `Keys().Signer` on a REST or gRPC client
returns a forwarding signer that POSTs each digest to the server; hand it to
`StartAgent` and the local socket serves signatures produced remotely. The
private half never moves.

## Go SDK

```go
import (
	gossh "golang.org/x/crypto/ssh"
	xkmsssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

signer, err := client.Keys().Signer(ctx, xkmsssh.GetKeyRequest{
	Scope: "user", Owner: "alice", Name: "commit-signing",
})
if err != nil {
	return err
}

sess, err := xkmsssh.StartAgent(ctx, xkmsssh.AgentOptions{
	Signers: []gossh.Signer{signer},
})
if err != nil {
	return err
}
defer sess.Stop(context.Background())

cmd := exec.CommandContext(ctx, "git", "commit", "-S", "-m", msg)
cmd.Env = append(os.Environ(), sess.Env...)
```

### `AgentOptions`

| Field | Type | Required | Meaning |
|---|---|---|---|
| `Signers` | `[]gossh.Signer` | yes | Identities to serve. At least one, none nil. Copied on entry. |
| `SocketDir` | `string` | no | Where the session **creates** its socket directory. Empty — the default — is the OS temporary directory. |

`SocketDir` is what a caller sets when the socket must be somewhere its own
policy admits: mounted into a sandboxed container, or under a tenant's root,
where a path in the OS temporary directory is not reachable. The session
creates the directory with mode 0700 (never more permissive; the process umask
can only clear bits), binds the socket inside it with mode 0600, and removes
the directory with the socket when the session ends. The resulting `SockPath` is `<SocketDir>/agent.sock` — computable before the call,
which is the point: a container mount specification has to name the socket
before there is a session to ask.

```go
sess, err := xkmsssh.StartAgent(ctx, xkmsssh.AgentOptions{
	Signers:   []gossh.Signer{signer},
	SocketDir: filepath.Join(projectRoot, ".xkms-agent"),
})
```

There is deliberately **no option for an existing directory to bind in**. The
session always creates the directory it binds inside, and `SocketDir` must not
already exist. A directory somebody else made cannot be validated safely: the
socket's 0600 mode does not protect its *pathname* — the containing directory
governs who may replace it — and checking that directory is inherently
check-then-use, since anyone who controls it can redirect the path between the
check and the bind. Closing that properly needs an anchored no-follow bind,
which `net.Listen("unix", path)` cannot express. An option whose validation
looks like a guarantee and is not is worse than no option.

What moves with `SocketDir` is the **parent**, and the parent is checked for
exactly what a parent can still do — hold a directory another user renames away
and replaces. It must exist and be private to this user: not a symlink, owned
by this user, not writable by group or other.

### `AgentSession`

| Member | Meaning |
|---|---|
| `SockPath string` | The socket path — the value of `SSH_AUTH_SOCK`. Absolute, and connectable when `StartAgent` returns, so a child with its own `Cmd.Dir` reaches the same socket. |
| `Env []string` | `{"SSH_AUTH_SOCK=<SockPath>"}`, ready to append to a child process's environment. |
| `Done() <-chan struct{}` | Closed once the agent has stopped and the socket (and an owned work dir) is gone. |
| `Stop(ctx) AgentShutdownReport` | Ends the session. Closes the listener and disconnects every attached client unconditionally, then joins the connection handlers within `ctx` and reports how many signing operations it had to abandon. Idempotent. |

### `AgentShutdownReport`

| Member | Meaning |
|---|---|
| `Abandoned int` | signature operations still **executing** when `Stop`'s context elapsed. Not connected clients and not parked handlers — an idle client holding the socket is not a signing operation, and reporting it as one would raise a security warning about work that never happened |
| `Clean() bool` | true when every handler finished within the bound |

A non-zero count is not an error and not a leak: those handlers hold no
connection. One may still complete a signature for a client that attached
*before* `Stop` began — no new authorization occurs, and no new client can
attach. See [`architecture.md`](architecture.md) for the full residual.

### Errors

| Error | Meaning |
|---|---|
| `*AgentInputError` | `Signers` empty or containing a nil entry, or the parent of `SocketDir` is not an existing directory; `Field` names it |
| `*AgentSocketDirExistsError` | `SocketDir` already exists — a directory, a file, or a socket. Nothing at the path is created, adopted or removed. `Path` names it; unwraps to `fs.ErrExist` |
| `*AgentInsecureSocketDirError` | the parent of `SocketDir` is a symlink, owned by another user, or writable by group or other |
| `*AgentWorkDirError` | the session's directory could not be created |
| `*AgentListenError` | the socket could not be bound. `errors.Is` the cause against `ErrAgentSocketInUse` (a live agent already listening — usually a reused `WorkDir`) or `ErrAgentPathOccupied` (the path holds something that is not a socket; it is never deleted) |
| `context.Canceled` / `context.DeadlineExceeded` | `ctx` was already dead at the call; no session is returned |

Match the typed errors with `errors.As` and the context errors with
`errors.Is`. Every one of them is re-exported by the SDK, so a consumer handles
failures without importing `pkg/`.

## Wire protocol

The socket speaks the standard **SSH agent protocol** (`ssh-agent(1)`), so any
client of it works unmodified. The served agent is read-only:

| Request | Behavior |
|---|---|
| `REQUEST_IDENTITIES` | lists the served public keys, commented `xkey-<n>` |
| `SIGN_REQUEST` | signs with the matching signer. **RSA never signs with SHA-1**: an unflagged request gets `rsa-sha2-256`, `SignatureFlagRsaSha512` gets `rsa-sha2-512`, and an RSA signer that cannot select an algorithm is refused |
| `ADD_IDENTITY`, `REMOVE_IDENTITY`, `REMOVE_ALL`, `LOCK`, `UNLOCK` | refused — the identity set is fixed at start |
| extensions | `ErrExtensionUnsupported` |
