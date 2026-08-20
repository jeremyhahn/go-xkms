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

// AgentOptions configures StartAgent. Signers come from Client.Keys().Signer —
// one per identity the agent should advertise.
type AgentOptions struct {
	// Signers are the identities to serve. At least one is required and none
	// may be nil. Whatever holds the private half — an in-process enclave, a
	// TPM, a PKCS#11 token, a remote xkms that signs over the wire — keeps it:
	// the agent socket carries signature requests, never key material.
	Signers []gossh.Signer
}

// There is deliberately no WorkDir option here.
//
// The session always creates its own private directory. A caller-chosen one
// cannot be validated safely: a socket's 0600 mode does not protect its
// pathname — the containing directory governs who may replace it — and
// checking the directory is inherently check-then-use, because an attacker
// controlling any ancestor can redirect the path between the check and the
// bind. Validating every component only moves the same race one level up.
//
// Closing that properly needs an anchored, no-follow bind, which the net
// package cannot express: net.Listen("unix", path) takes a pathname, not a
// directory descriptor. Rather than ship a check that looks like a guarantee
// and is not, the option is absent and the directory is one this process just
// created, with a unique name, inside a location the OS already controls.

// StartAgent serves the given signers over an ephemeral in-process SSH agent
// socket and returns the live session. There is no connection target: this is
// the signing primitive, for anything that speaks the ssh-agent protocol
// without dialing a host — `git commit -S` under `gpg.format=ssh`, `ssh-keygen
// -Y sign`, age — where Keys().Signer gives an in-process ssh.Signer but the
// tool needs a socket.
//
// The socket exists by the time StartAgent returns, so the path can go straight
// into a child process's environment. It lives in a private directory this
// process creates and removes; the caller does not choose the location, because
// a directory anyone else can reach is a directory in which the socket can be
// substituted.
//
// Lifetime: the session ends at the first of (*AgentSession).Stop or
// cancellation of ctx. Either way the socket file is removed, along with the
// work directory when the session created it. Stop blocks until that has
// happened; a caller that cancels ctx instead waits on Done to observe it.
//
// No host-key semantics are implied and none are available. StartAgent neither
// seeds nor consults known_hosts, because a signature has no host to verify. A
// caller that does have a connection target wants StartConnect, which layers
// pin seeding and first-contact sync over this same agent.
func StartAgent(ctx context.Context, opts AgentOptions) (*AgentSession, error) {
	return pkgagent.StartSession(ctx, pkgagent.Request{Signers: opts.Signers})
}
