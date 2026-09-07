# SSH Agent Sessions — Engineering Contract

> **Status: NORMATIVE** · Feature: `ssh-agent-sessions` · Repo: `go-xkms` · Last verified: 2026-09-06

## Exported surface — `sdk/go/client/ssh`

The SDK is the only surface a consumer may reach.

```go
type AgentOptions struct {
	Signers   []gossh.Signer // identities to serve
	SocketDir string         // where the session CREATES its socket directory; empty = OS temp
}

type AgentSession = pkgagent.Session

func StartAgent(ctx context.Context, opts AgentOptions) (*AgentSession, error)

type AgentInputError             = pkgagent.InputError            // missing or invalid option
type AgentWorkDirError           = pkgagent.WorkDirError          // the directory could not be created
type AgentListenError            = pkgagent.ListenError           // socket could not be bound
type AgentSocketDirExistsError   = pkgagent.SocketDirExistsError  // SocketDir already exists
type AgentInsecureSocketDirError = pkgagent.InsecureWorkDirError  // SocketDir's parent is not private
```

There is still no option for an **existing** directory to bind in: `SocketDir`
is a location, and the session always creates the directory it binds inside.
See [`architecture.md`](architecture.md).

## Exported surface — `pkg/ssh/agent`

```go
type Request struct {
	Signers   []ssh.Signer
	WorkDir   string // an EXISTING directory the caller owns and keeps
	SocketDir string // a directory the session creates, owns and removes
}

type Session struct {
	SockPath string   // agent socket path
	Env      []string // {"SSH_AUTH_SOCK=<SockPath>"}
}

func StartSession(ctx context.Context, req Request) (*Session, error)
func SocketPath(workDir string) string
func (s *Session) Done() <-chan struct{}

type ShutdownReport struct {
	Abandoned int // signature operations still EXECUTING when the bound elapsed
}

func (r ShutdownReport) Clean() bool
func (s *Session) Stop(ctx context.Context) ShutdownReport

func Serve(ctx context.Context, socketPath string, a sshagent.Agent) error // pre-existing

type SocketDirExistsError struct{ Path string } // unwraps to fs.ErrExist

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
9. **The session ends once, on either path.** `Stop` or ctx cancellation,
   whichever comes first; both converge on one reaper. `Stop` is idempotent,
   including on an already-cancelled session.
10. **Shutdown disconnects live clients, and terminates.** Closing the listener
   is not enough: an already-attached client would keep signing through an
   ended session. Closing the listener and disconnecting every live connection
   are unconditional, and together they are what make the session unusable.
   Joining the handlers afterwards happens **within the caller's context**,
   because a handler stuck inside an uninterruptible `Signer.Sign` — a TPM
   awaiting touch, a stalled KMS — cannot be woken and does not need to be
   waited for: the connection it would write its signature to is already
   closed, so it can answer nobody. `Stop` returns a `ShutdownReport` naming
   any it abandoned; waiting without a bound hands the caller's shutdown to a
   wedged device, and a bounded stop that reported nothing would be the same
   surprise as no bound at all. The work directory is reaped by the session's
   own reaper on the default bound, so it goes even when nobody calls `Stop`.
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
14. **`SocketDir` gives the caller the location, never the directory.** The
   session creates `SocketDir` itself with `os.Mkdir` (mode 0700; the mode is
   not restated afterwards, because the process umask can only CLEAR bits, so
   what lands is never more permissive than 0700 — and "no group or other
   access" is the whole of what the socket's safety rests on), binds
   `agent.sock` inside it, and removes the directory with the socket when the
   session ends. Because it is created here, the invariant behind mode 0600 —
   that no other user can traverse into the socket's directory — holds exactly
   as it does for the default temporary directory; nothing is inherited from a
   directory somebody else made. Consequences, each load-bearing:
   - **An existing path is refused**, with `*SocketDirExistsError` (unwrapping
     to `fs.ErrExist`), whether it holds a directory, a file, or a socket.
     Adopting one would put a signing oracle in a directory on terms this
     package cannot see; clearing one would delete whatever the caller keeps
     there, up to and including another live agent. `os.Mkdir` makes the test
     and the claim the same operation, so there is no window between them.
   - **The parent is checked, never created**, by the same `checkWorkDir` a
     supplied `WorkDir` passes: an existing, non-symlink, self-owned directory
     that is not group- or world-writable, else `*InsecureWorkDirError`.
     Creating the socket's own directory closes the substitution window inside
     it; nothing closes one in a parent another user can write to, where the
     whole directory can be renamed away and replaced.
   - **`SocketDir` and `WorkDir` are mutually exclusive** —
     `*InputError{Field: "SocketDir (WorkDir is also set)"}`. They say opposite
     things about who owns the directory, and therefore about whether it
     survives shutdown; preferring one silently would leave the caller
     believing the other.
   - **`SocketPath(SocketDir)` is known before the call**, which is why the
     option exists: a consumer that must name the socket in a container mount
     specification cannot wait for the session to start to learn it. A relative
     `SocketDir` is resolved against *this* process's directory on entry, once,
     so the resulting `SockPath` is absolute and means the same thing to a
     process with its own working directory and PID namespace.

## Errors

| Error | Raised when |
|---|---|
| `*InputError{Field}` | `Signers` empty or containing a nil (including typed-nil) entry; `WorkDir` supplied but not an existing directory; `SocketDir`'s parent not an existing directory; both `WorkDir` and `SocketDir` supplied |
| `*InsecureWorkDirError{Path, Reason}` | supplied `WorkDir`, or the parent of `SocketDir`, is a symlink, foreign-owned, or group/world-writable |
| `*SocketDirExistsError{Path}` | `SocketDir` already exists. Unwraps to `fs.ErrExist`; nothing at the path is created, adopted or removed |
| `*UnsupportedAlgorithmError{Algorithm}` | an RSA signer that cannot select an algorithm, so only SHA-1 would remain |
| `*WorkDirError{Err}` | the session's directory could not be created — the temporary one, or `SocketDir` for a reason other than occupancy |
| `*ListenError{Err}` | the socket directory, bind, or chmod failed; or the path is occupied — `errors.Is` the cause against `ErrSocketInUse` (a live agent is listening) or `ErrPathOccupied` (not a socket) |
| `*UnknownKeyError{Format}` | a sign request names a key the session does not serve |
| `*AcceptError{Err}` | the listener failed for a reason other than shutdown |
| `ErrUnsupported` | `Add` / `Remove` / `Lock` / `Unlock` — the agent is read-only |

All are typed; none are `fmt.Errorf`. `WorkDirError`, `ListenError`,
`AcceptError` and `SocketDirExistsError` implement `Unwrap`.

## Configuration

None. There is no config file, environment variable, or flag: everything the
session needs arrives in `AgentOptions`. The only environment involved is the
`SSH_AUTH_SOCK` the session *produces*.

## Tests

| Tier | Location | Covers |
|---|---|---|
| unit | `sdk/go/client/ssh/agent_test.go` | The SDK surface, hermetically — in-process ssh-agent protocol, no external binary. A key generated through the SDK is advertised on the socket and its signatures verify under it; the agent refuses every mutating request; both lifetime paths, including a client held across `Stop` losing its ability to sign; cancelled context; typed bind failure; and the `SocketDir` contract as a consumer meets it — honoured path and modes, refusal of an existing path and of an insecure parent through the SDK's own error aliases, removal on `Stop`, and signing from another working directory. |
| unit | `pkg/ssh/agent/session_socketdir_test.go` | `SocketDir` end to end: the socket lands at the predicted path with a 0700 directory and a 0600 socket and signs; the directory goes on both exit paths and the parent survives; an existing directory, an existing file, an impossible name, a missing parent, a world-writable parent, a symlinked parent and a request carrying both directory options are each refused with their own typed error and create nothing; a relative `SocketDir` resolves once, against this process, and the socket then signs for a client in a different working directory. |
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

`pkg/ssh/agent` coverage: 94.4%.
