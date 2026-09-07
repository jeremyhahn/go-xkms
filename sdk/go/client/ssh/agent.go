// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	"context"

	gossh "golang.org/x/crypto/ssh"

	pkgagent "github.com/jeremyhahn/go-xkms/pkg/ssh/agent"
)

// AgentSession is a running agent-only session: an ephemeral SSH agent socket
// serving xkms-held keys, with no connection target. Hand SockPath to a child
// process as SSH_AUTH_SOCK (or append Env to its environment), then Stop when
// it exits; Done reports when the socket is gone.
type AgentSession = pkgagent.Session

// AgentShutdownReport is what (*AgentSession).Stop returns: the number of
// in-flight signing operations still running when the caller's bound elapsed.
// A non-zero count is not a leak — those handlers hold no connection, because
// Stop disconnects every client before it waits — but one of them may still
// complete a signature for a client that attached before Stop began. See the
// type's own documentation for the full residual.
type AgentShutdownReport = pkgagent.ShutdownReport

// AgentInputError reports a missing or invalid AgentOptions field.
type AgentInputError = pkgagent.InputError

// AgentWorkDirError reports a failure to create the session's temporary work
// directory.
type AgentWorkDirError = pkgagent.WorkDirError

// AgentListenError reports a failure to bind the agent socket.
type AgentListenError = pkgagent.ListenError

// ErrAgentSocketInUse is the cause inside an *AgentListenError when a live
// agent is already listening at the socket path — usually a WorkDir reused by
// a session that has not ended. Match it with errors.Is.
var ErrAgentSocketInUse = pkgagent.ErrSocketInUse

// ErrAgentPathOccupied is the cause inside an *AgentListenError when the socket
// path names something that is not a socket. It belongs to the caller and is
// never removed. Match it with errors.Is.
var ErrAgentPathOccupied = pkgagent.ErrPathOccupied

// AgentSocketDirExistsError reports that the directory named by
// AgentOptions.SocketDir already exists. The session creates that directory
// itself so that it owns what the socket sits in; an existing one is refused
// rather than adopted or cleared. It unwraps to fs.ErrExist.
type AgentSocketDirExistsError = pkgagent.SocketDirExistsError

// AgentInsecureSocketDirError reports that the parent of AgentOptions.SocketDir
// cannot hold an agent socket safely — it is a symlink, is owned by another
// user, or is writable by group or other. A directory another user can write to
// is one in which the session's own directory can be replaced between the bind
// and the child process's connect.
type AgentInsecureSocketDirError = pkgagent.InsecureWorkDirError

// AgentOptions configures StartAgent. Signers come from Client.Keys().Signer —
// one per identity the agent should advertise.
type AgentOptions struct {
	// Signers are the identities to serve. At least one is required and none
	// may be nil. Whatever holds the private half — an in-process enclave, a
	// TPM, a PKCS#11 token, a remote xkms that signs over the wire — keeps it:
	// the agent socket carries signature requests, never key material.
	Signers []gossh.Signer

	// SocketDir names the directory the session creates for its socket. Empty
	// — the default — puts it in the OS temporary directory, unchanged from
	// before this option existed.
	//
	// Set it when the socket has to be somewhere specific: mounted into a
	// sandboxed container, or under a tenant's own root, where a path in the
	// OS temporary directory is outside what the caller's mount policy admits.
	// The session creates the directory with mode 0700, binds the socket
	// inside it with mode 0600, and removes the directory with the socket when
	// the session ends. The resulting path is SockPath — predictable before
	// the call as <SocketDir>/agent.sock — and absolute, so a process with its
	// own working directory and PID namespace can use it as SSH_AUTH_SOCK.
	//
	// The directory must not already exist: the caller chooses the location,
	// the session owns the directory. An existing path is refused with an
	// *AgentSocketDirExistsError, never adopted (its contents are on terms
	// this package cannot see) and never cleared (that would delete somebody
	// else's live agent). The parent must exist and be private to this user —
	// not a symlink, owned by this user, not writable by group or other — or
	// the call fails with an *AgentInsecureSocketDirError.
	//
	// What the option does NOT do is hand the caller the directory the socket
	// binds in. That distinction is the whole of the safety argument, and the
	// note below explains why.
	SocketDir string
}

// There is deliberately no option for an existing directory to bind in.
//
// SocketDir is a location, not a directory: the session always binds inside a
// directory it created itself. An existing caller-chosen one cannot be
// validated safely — a socket's 0600 mode does not protect its pathname, the
// containing directory governs who may replace it, and checking that directory
// is inherently check-then-use, because anyone controlling it can swap what the
// path names between the check and the bind. Validating every component only
// moves the same race one level up.
//
// Closing that properly needs an anchored, no-follow bind, which the net
// package cannot express: net.Listen("unix", path) takes a pathname, not a
// directory descriptor. So the check that could not be made into a guarantee is
// not offered as one. What SocketDir moves is the parent, and the parent is
// checked for exactly what a parent can still do — hold a directory another
// user may replace — while the directory holding the socket remains one this
// process created, with mode 0700, in the same call that binds inside it.

// StartAgent serves the given signers over an ephemeral in-process SSH agent
// socket and returns the live session. There is no connection target: this is
// the signing primitive, for anything that speaks the ssh-agent protocol
// without dialing a host — `git commit -S` under `gpg.format=ssh`, `ssh-keygen
// -Y sign`, age — where Keys().Signer gives an in-process ssh.Signer but the
// tool needs a socket.
//
// The socket exists by the time StartAgent returns, so the path can go straight
// into a child process's environment. It lives in a private directory this
// process creates and removes. The caller may choose where that directory goes
// — opts.SocketDir, for a socket that has to be reachable by a sandbox — but
// never hand over an existing directory, because a directory anyone else can
// reach is a directory in which the socket can be substituted.
//
// Lifetime: the session ends at the first of (*AgentSession).Stop or
// cancellation of ctx. Either way the socket file is removed, along with the
// private work directory. Stop takes its own context: it disconnects every
// attached client unconditionally, then joins the connection handlers within
// that context and returns an AgentShutdownReport naming any it had to abandon
// — a handler stuck inside an uninterruptible Sign cannot be woken, and waiting
// on one without a bound would hand a caller's shutdown to a wedged device. A
// caller that cancels ctx instead waits on Done to observe the end.
//
// No host-key semantics are implied and none are available. StartAgent neither
// seeds nor consults known_hosts, because a signature has no host to verify. A
// caller that does have a connection target wants StartConnect, which layers
// pin seeding and first-contact sync over this same agent.
func StartAgent(ctx context.Context, opts AgentOptions) (*AgentSession, error) {
	return pkgagent.StartSession(ctx, pkgagent.Request{
		Signers:   opts.Signers,
		SocketDir: opts.SocketDir,
	})
}
