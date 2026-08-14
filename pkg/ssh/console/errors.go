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

package console

// InputError indicates a required argument was nil or empty.
type InputError struct {
	Field string
}

func (e *InputError) Error() string { return "ssh/console: missing required field: " + e.Field }

// SessionError wraps a failure opening or configuring the SSH session/PTY.
type SessionError struct {
	Err error
}

func (e *SessionError) Error() string { return "ssh/console: session: " + e.Err.Error() }
func (e *SessionError) Unwrap() error { return e.Err }

// ClosedError indicates an operation on a closed console.
type ClosedError struct{}

func (e *ClosedError) Error() string { return "ssh/console: console is closed" }

// WriteClosedError indicates a Write after CloseWrite: the console's write
// half has been shut and the remote has already seen EOF on its stdin.
type WriteClosedError struct{}

func (e *WriteClosedError) Error() string { return "ssh/console: write half is closed" }
