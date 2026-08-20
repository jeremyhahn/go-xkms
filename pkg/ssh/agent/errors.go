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

package agent

import "errors"

// ErrUnsupported is returned by the mutating agent operations (Add / Remove /
// Lock / Unlock) — this agent is read-only.
var ErrUnsupported = errors.New("ssh/agent: operation not supported (read-only agent)")

// UnknownKeyError is returned by Sign when no served signer matches the
// requested public key.
type UnknownKeyError struct {
	Format string
}

func (e *UnknownKeyError) Error() string {
	return "ssh/agent: no signer for key of type " + e.Format
}

// ErrSocketInUse reports that an agent is already listening at the socket path.
// Binding would unlink a live session's socket, silently redirecting the
// children that hold that path in SSH_AUTH_SOCK onto a different key set.
var ErrSocketInUse = errors.New("ssh/agent: an agent is already listening at the socket path")

// ErrPathOccupied reports that the socket path is occupied by something this
// session will not use: a file that is not a socket, or a socket no agent
// answers (a leftover from a crashed run). Nothing at the path is ever removed
// -- it belongs to whoever owns the directory.
var ErrPathOccupied = errors.New("ssh/agent: the socket path is occupied by a file that is not a socket")

// InsecureWorkDirError reports a supplied work directory that cannot hold an
// agent socket safely. A unix socket's own permissions do not protect its
// pathname -- the containing directory governs who can replace it -- so a
// shared or foreign-owned directory would let another user substitute their
// own agent at the socket path a child process is about to trust.
type InsecureWorkDirError struct {
	Path   string
	Reason string
}

func (e *InsecureWorkDirError) Error() string {
	return "ssh/agent: work directory " + e.Path + " " + e.Reason +
		"; an agent socket needs a directory private to this user"
}

// InputError reports a missing or invalid field in a StartSession Request.
type InputError struct {
	Field string
}

func (e *InputError) Error() string {
	return "ssh/agent: missing or invalid " + e.Field
}

// WorkDirError wraps a failure to create the session's temporary work
// directory.
type WorkDirError struct {
	Err error
}

func (e *WorkDirError) Error() string { return "ssh/agent: work directory: " + e.Err.Error() }
func (e *WorkDirError) Unwrap() error { return e.Err }

// UnsupportedAlgorithmError is returned when a served signer cannot produce a
// signature with an approved algorithm -- an RSA signer that cannot select one,
// which would leave only the legacy SHA-1 ssh-rsa.
type UnsupportedAlgorithmError struct {
	Algorithm string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return "ssh/agent: signer for " + e.Algorithm +
		" cannot select a signature algorithm; refusing to fall back to SHA-1"
}

// ListenError wraps a failure to create or bind the agent socket.
type ListenError struct {
	Err error
}

func (e *ListenError) Error() string { return "ssh/agent: listen: " + e.Err.Error() }
func (e *ListenError) Unwrap() error { return e.Err }

// AcceptError wraps a failure to accept an agent connection.
type AcceptError struct {
	Err error
}

func (e *AcceptError) Error() string { return "ssh/agent: accept: " + e.Err.Error() }
func (e *AcceptError) Unwrap() error { return e.Err }
