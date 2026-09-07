# SSH Agent Sessions — Architecture

> **Status: NORMATIVE** · Feature: `ssh-agent-sessions` · Repo: `go-xkms` · Last verified: 2026-09-06

## The problem

A tool that signs with an SSH key does not necessarily connect to anything.
`git commit -S` under `gpg.format=ssh`, `ssh-keygen -Y sign`, and `age` all
speak the ssh-agent protocol, and none of them have a host.

xkms could already hand out an `ssh.Signer` (`Keys().Signer`) and could already
serve a key over an agent socket — but only as one step inside launching a
connection, behind a `Host`/`Port`/`User` and a seeded `known_hosts`. So a
signing consumer had an in-process signer where it needed a **socket**, and the
only socket on offer demanded a connection target it did not have.

The two workarounds available to such a consumer are both worse than the gap:

- **A `gpg.ssh.program` helper binary.** Puts a signing oracle on disk and a
  process boundary inside the trusted path, for the sole purpose of reaching a
  key the calling process already holds.
- **Calling the connection launcher with a placeholder host** plus the flags
  that suppress host-key handling. This works only by accident of what the
  launcher validates today. The day validation tightens, commit signing breaks
  — and it breaks *silently*, because a signature that was never produced looks
  the same as one nobody checked.

## Shape chosen: an agent-only session, hostless by construction

`agent.StartSession` serves signers over an ephemeral socket and does nothing
else. The capability that already existed inside the connection launcher is
exposed directly, in its own right:

```
                       ssh.Signer (enclave / TPM / PKCS#11 / remote xkms)
                                        |
                            agent.StartSession(ctx, Request)
                                        |
                          ephemeral unix socket, mode 0600
                                        |
              SSH_AUTH_SOCK -> git commit -S / ssh-keygen -Y sign / age
```

`pkg/ssh/connect` is now a **consumer of this session**, not a second copy of
it: it starts one, then adds the host semantics a connection needs — pin
seeding, first-contact prompting, sync-back. There is exactly one agent
implementation and one socket lifetime in the repository.

Its error contract is unchanged by the move: every `connect` setup failure is
still a `*connect.LaunchError`, agent failures included (`Op: "agent session"`),
with the underlying `*agent.ListenError` reachable through `Unwrap`. A caller
matching `*LaunchError` does not start missing failures because the agent moved
into its own package.

The two packages' `WorkDir` options mean deliberately different things, and the
difference is ownership. `connect.Request.WorkDir` names where a connection's
scratch area *goes* — socket and temp `known_hosts` side by side — so `connect`
creates it. `agent.Request.WorkDir` must already exist, because a session that
conjured a directory would not own it and would therefore leave it behind on
every run.

`agent.Request.SocketDir` is the third point on that same axis, and the one the
SDK exposes: a directory the session **creates**, owns, and removes. It exists
because ownership and location are separable questions that the `WorkDir`
option ran together. A caller can need the socket somewhere specific — inside a
tree its sandbox mount policy admits, rather than in the OS temporary directory
— without needing, or being able to vouch for, the directory the socket binds
in. So the caller names the location and the session still makes the directory,
which is what keeps the 0700 guarantee a construction rather than a claim.

## Boundaries

**No host-key semantics, deliberately.** The session neither seeds nor consults
`known_hosts`. This is not "host checking turned off" — there is no host, so
there is nothing to check. The distinction matters because the rejected
placeholder-host workaround *looks* the same from the outside and is not:
there, host verification was suppressed for a connection that really happened.
A caller that does have a target uses `connect.Start` / `StartConnect`.

**No key material.** Only an `ssh.Signer` is held. Whatever holds the private
half keeps it — an in-process enclave, a TPM, a PKCS#11 token, or a remote xkms
that signs over the wire. The socket carries signature requests and public-key
listings; it never carries a private key, and the consumer writes only the
public half to disk as `user.signingkey`.

**Read-only agent.** `Add`, `Remove`, `Lock`, and `Unlock` are unsupported: the
identity set is fixed when the session starts and frozen by a copy, so a caller
that mutates its own slice afterwards cannot change what a live signing oracle
serves.

## Lifetime, and why it is stated rather than implied

The session ends at the first of `Stop` or cancellation of the context passed
to `StartSession`. Either way the socket file is removed, and a work directory
the session created goes with it. `Stop` reports what it had to abandon;
`Done()` reports it for a caller that cancelled the context instead.

An agent socket is a signing oracle for anyone who can connect to it. A socket
whose owner has moved on is exactly the failure this contract exists to
exclude, so there is no path that leaves one behind: both exit paths converge
on a single reaper.

**Closing the listener is not shutdown.** A client that connected before the
session ended holds a socket of its own, and unlinking the pathname does
nothing to it — it would go on issuing sign requests through a session its
owner believes is over, which is precisely the unwatched oracle above wearing
a different hat. Shutdown therefore closes every attached connection and joins
its handler before reporting completion. When `Stop` returns, or `Done()`
closes, there is no usable signing path left: not a new one, and not an old
one.

**And that is why the bound belongs to the caller, with the residual named.**
A handler stuck inside an uninterruptible `Signer.Sign` — a TPM awaiting touch,
a stalled KMS — cannot be woken by closing its connection. Waiting on it forever
hands control of the caller's shutdown to a wedged device; giving up silently
re-introduces, as an undocumented surprise, the very thing the drain was built
to prevent. So `Stop` takes a context and returns a `ShutdownReport` counting
what it abandoned.

The residual, stated so a caller decides rather than discovers: an abandoned
handler may still deliver a signature to the client that asked for it, **if that
client attached before `Stop` began**. No new authorization occurs — that client
was already being served by an authorized session, and no new one can attach,
because the listener closed and every connection was dropped before any waiting
started. A caller that cannot accept this tears down its process; one that can,
because the abandoned work is its own, carries on.

A context-aware signing seam would remove even that, and it is deliberately not
built here: it reaches into how every backend constructs its `crypto.Signer`,
hardware included, and the typed report is sufficient for this consumer class.

## Rejected alternatives

**Let the caller hand over an existing directory to bind in.** The SDK has no
such option, and `SocketDir` is not one: it names where the session creates its
directory, not a directory to adopt. A socket's own permissions do not protect
its pathname — the containing directory decides who can unlink and re-bind it —
and validating a supplied directory is inherently check-then-use: an attacker
controlling it redirects the path between the check and the bind, and
validating every component moves the same race one level up. The honest fix is
an anchored no-follow bind, which `net.Listen("unix", path)` cannot express
because it takes a pathname rather than a directory descriptor. So the session
always creates the directory it binds in, and the option that could not be made
safe is still absent. `pkg/ssh/connect` keeps a directory parameter because it
supplies one it created itself.

**Put the socket wherever the caller says, unconditionally.** Rejected as the
shape of the location option, because the parent still decides something the
session cannot: a directory created inside a world-writable parent can be
renamed away and replaced whole, and the child reading `SSH_AUTH_SOCK` would
then reach somebody else's agent. The parent is therefore held to the same test
a supplied `WorkDir` passes. This does refuse the OS temporary directory as a
`SocketDir` parent, which is not an inconsistency — a caller that wants that
location leaves `SocketDir` empty and gets it, through `os.MkdirTemp`, on the
platform's own per-user isolation rather than on a claim this package would be
making about a directory anyone can write to.

**Return a directory the caller then populates, or let it pre-create the
directory and pass it.** Both were the same thing in different clothes: an
existing directory at bind time, which is the case above. Refusing an existing
path with `os.Mkdir` is what makes "the session owns this directory" a fact
established by the same syscall that tests it, rather than a stat followed by a
hope.

**Serve on a caller-supplied listener.** Would let a consumer share one socket
across sessions, at the cost of making the lifetime contract the caller's
problem — the one thing most worth taking away from them here.

**Take a key reference instead of signers.** `StartAgent(ctx, ref)` reads
nicely, but resolving the key inside would bind the entry point to one
transport's `Client`. Taking resolved `ssh.Signer` values keeps it working for
every backend, including a remote xkms whose signer forwards each digest over
the wire, and mirrors `StartConnect`, which takes a signer for the same reason.

**Bind the socket inside the serving goroutine** (the shape the connection
launcher used, with a 3-second poll for the socket to appear). Rejected: it
turns a bind failure into a timeout, forces a `time.Sleep` poll loop, and makes
"is the socket ready?" a question the caller has to ask. Binding synchronously
answers it at the call.
