# SSH Agent Sessions — Engineering Contract

> **Status: NORMATIVE** · Feature: `ssh-agent-sessions` · Repo: `go-xkms` · Last verified: 2026-08-20

## Exported surface — `sdk/go/client/ssh`

The SDK is the only surface a consumer may reach.

```go
type AgentOptions struct {
	Signers []gossh.Signer // no WorkDir: see architecture.md
}

type AgentSession = pkgagent.Session

func StartAgent(ctx context.Context, opts AgentOptions) (*AgentSession, error)

type AgentInputError   = pkgagent.InputError   // missing or invalid option
type AgentWorkDirError = pkgagent.WorkDirError // temp dir could not be created
type AgentListenError  = pkgagent.ListenError  // socket could not be bound
```

## Exported surface — `pkg/ssh/agent`

```go
type Request struct {
	Signers []ssh.Signer
	WorkDir string
}

type Session struct {
	SockPath string   // agent socket path
	Env      []string // {"SSH_AUTH_SOCK=<SockPath>"}
}

func StartSession(ctx context.Context, req Request) (*Session, error)
func SocketPath(workDir string) string
func (s *Session) Done() <-chan struct{}
func (s *Session) Stop()

func Serve(ctx context.Context, socketPath string, a sshagent.Agent) error // pre-existing

// The raw binder is deliberately NOT exported. net.Listen binds before the
// socket mode is applied, so for an arbitrary path there is a window in which
// the socket carries whatever the umask left it -- and tightening the mode
// afterwards does not disconnect anyone who connected during it. What closes
// the window is the containing directory being 0700, which only StartSession
// can promise.
```

## Invariants

1. **The socket is bound before `StartSession` returns.** `SockPath` is
   connectable at the call, so it can go straight into a child process's
   environment. A bind failure is an `*ListenError` return, never a socket that
   never appears.
2. **`SockPath` is absolute.** It leaves this process as `SSH_AUTH_SOCK` for a
   child usually started with its own working directory, so a relative path
   would resolve against the child's directory rather than the session's — and
   against wherever this process had chdir'd by shutdown. A relative `WorkDir`
   is resolved on entry.
3. **The identity set is frozen.** `Signers` is copied. A caller mutating its
   own slice afterwards cannot change what the live agent serves, and cannot
   introduce a nil past validation.
4. **A supplied `WorkDir` must be private to this user.** Not a symlink (it
   could be re-pointed between the check and the bind), owned by the effective
   user, and not group- or world-writable — otherwise `*InsecureWorkDirError`.
   A unix socket's own 0600 mode does not protect its *pathname*: the
   containing directory governs who may replace it, so a shared directory lets
   another user bind their agent where a child is about to send signing
   requests. This also closes the bind-to-chmod window in `Listen`, since in a
   0700 directory nobody else can traverse in to reach the socket.
5. **RSA never signs with SHA-1.** An unflagged request is an ssh-agent
   client's default, not a choice, and x/crypto's default for RSA is the legacy
   `ssh-rsa`. RSA requests are signed `rsa-sha2-256` (or `-512` when flagged);
   an RSA signer that cannot select an algorithm is refused with
   `*UnsupportedAlgorithmError` rather than falling back.
6. **At least one non-nil signer.** Empty or nil-containing `Signers` is
   `*InputError{Field: "Signers"}` — a socket that can sign nothing is a
   listener with no purpose and a misleading `SSH_AUTH_SOCK`. A **typed** nil
   (a nil pointer boxed in an `ssh.Signer`) is rejected too: an interface nil
   check misses it and the first `PublicKey` call would panic in the serving
   goroutine, taking the process with it.
7. **A dead context is refused.** `StartSession` returns `ctx.Err()` when the
   context is already cancelled or expired, rather than a session whose socket
   the reaper is already removing — which would hand the caller a nil error and
   an `SSH_AUTH_SOCK` that answers nothing.
8. **Socket mode is 0600.** The socket is a signing oracle for whoever can
   connect to it.
9. **The session ends once, on either path.** `Stop()` or ctx cancellation,
   whichever comes first; both converge on one reaper. `Stop()` blocks until the
   socket is gone and is idempotent, including on an already-cancelled session.
10. **Shutdown disconnects live clients, and terminates.** Closing the listener
   is not enough: an already-attached client would keep signing through an
   ended session. Closing the listener and disconnecting every live connection
   are unconditional, and together they are what make the session unusable.
   Joining the handlers afterwards is bounded (`handlerJoinTimeout`), because a
   handler stuck inside an uninterruptible `Signer.Sign` — a TPM awaiting touch,
   a stalled KMS — cannot be woken and does not need to be waited for: the
   connection it would write its signature to is already closed, so it can
   answer nobody. Waiting forever would hang `Stop()` and leave the work
   directory unreaped to guard against an oracle with no one to talk to.
   The socket file is unlinked by closing the listener and **never again**:
   joining slow handlers takes long enough for a successor session on the same
   `WorkDir` to have bound the path, and a late removal would delete that live
   socket rather than this dead one.
11. **Nothing at the socket path is ever removed.** An occupied path is
   refused: `*ListenError` wrapping `ErrSocketInUse` when an agent answers a
   (bounded) dial there, `ErrPathOccupied` otherwise — a file that is not a
   socket, or a socket nobody answers. Clearing a leftover looks helpful and
   cannot be done safely: inspect, unlink and bind are three steps, and between
   them another process can bind its own live agent at that path, which the
   unlink would then destroy — redirecting its children onto a different key
   set. Refusing costs an error a caller can act on; guessing costs someone
   else's key isolation. A leftover from a crashed run belongs to whoever owns
   the directory. Nothing in this path mutates the filesystem, so there is no
   inspect-then-act window at all.
12. **Work-directory ownership follows creation.** A directory the session
   created is removed when it ends; a caller-supplied `WorkDir` is left in
   place (this is how `pkg/ssh/connect` keeps its `known_hosts` alongside).
   A supplied `WorkDir` that is not an existing directory is
   `*InputError{Field: "WorkDir"}` rather than something created on the
   caller's behalf — the session must not leave behind what it does not own.
13. **No host-key state is read or written.** Any change adding it belongs in
   `pkg/ssh/connect`.

## Errors

| Error | Raised when |
|---|---|
| `*InputError{Field}` | `Signers` empty or containing a nil (including typed-nil) entry; `WorkDir` supplied but not an existing directory |
| `*InsecureWorkDirError{Path, Reason}` | supplied `WorkDir` is a symlink, foreign-owned, or group/world-writable |
| `*UnsupportedAlgorithmError{Algorithm}` | an RSA signer that cannot select an algorithm, so only SHA-1 would remain |
| `*WorkDirError{Err}` | the temporary work directory could not be created |
| `*ListenError{Err}` | the socket directory, bind, or chmod failed; or the path is occupied — `errors.Is` the cause against `ErrSocketInUse` (a live agent is listening) or `ErrPathOccupied` (not a socket) |
| `*UnknownKeyError{Format}` | a sign request names a key the session does not serve |
| `*AcceptError{Err}` | the listener failed for a reason other than shutdown |
| `ErrUnsupported` | `Add` / `Remove` / `Lock` / `Unlock` — the agent is read-only |

All are typed; none are `fmt.Errorf`. `WorkDirError`, `ListenError`, and
`AcceptError` implement `Unwrap`.

## Configuration

None. There is no config file, environment variable, or flag: everything the
session needs arrives in `AgentOptions`. The only environment involved is the
`SSH_AUTH_SOCK` the session *produces*.

## Tests

| Tier | Location | Covers |
|---|---|---|
| unit | `sdk/go/client/ssh/agent_test.go` | The SDK surface, hermetically — in-process ssh-agent protocol, no external binary. A key generated through the SDK is advertised on the socket and its signatures verify under it; the agent refuses every mutating request; both lifetime paths, including a client held across `Stop` losing its ability to sign; cancelled context; typed bind failure. |
| unit | `pkg/ssh/agent/session_test.go` | Bind-before-return (a *connectable* socket, not merely a path), signature round-trip, `Env` handoff, socket mode, Stop idempotence and Stop-after-cancel, borrowed vs. owned work dir, multi-identity, frozen signers, live clients disconnected on both exit paths, and every input / bind / work-dir / dead-context failure branch. |
| integration | `test/integration/sshagent/git_signing_test.go` (`-tags integration`, `make integration-test-sshagent`) | The consumer scenario end to end: a real `git commit -S` under `SSH_AUTH_SOCK`, `git verify-commit` against an allowed-signers file naming that key, a disk walk asserting no private-key material was written, socket and work dir gone after ctx cancel. A negative twin runs the identical git invocation with no session and requires it to fail, so a pass proves the session is what made signing work. |

The git path is integration-tier because it shells out to the host's `git` and
`ssh-keygen`; the unit tier stays in-memory and fast, as the repository's
testing contract requires. **No skip guards anywhere**: the acceptance test
*fails* rather than skipping when a tool is missing (integration tests run in
the devcontainer, where both are present, so a missing one is a broken
environment), and every branch is reachable regardless of the effective user —
the bind-failure case uses an over-long socket path rather than file
permissions, which root ignores.

Every assertion has been mutation-verified. The one worth recording: corrupting
the signature returned by `SignWithFlags` still yields a commit carrying a
`gpgsig` header — only `verify-commit` catches it. Asserting the header alone
would pass a mutant that signs garbage.

`pkg/ssh/agent` coverage: 95.8%.
