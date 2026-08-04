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
