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

package session

import "time"

// NilInputError is returned when a required DialRequest field is
// missing (nil / zero).
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "ssh/session: nil input: " + e.Field
}

// DialError wraps a failure to establish the TCP connection.
type DialError struct {
	Host string
	Err  error
}

// Error implements the error interface.
func (e *DialError) Error() string {
	return "ssh/session: dial " + e.Host + ": " + e.Err.Error()
}

// Unwrap returns the underlying network error.
func (e *DialError) Unwrap() error { return e.Err }

// HandshakeError wraps a failure in the SSH handshake (including host
// key verification and authentication rejection). The underlying cause
// is preserved via Unwrap so callers can detect specific cases (e.g.,
// *known_hosts.MismatchError) with errors.As.
type HandshakeError struct {
	Host string
	User string
	Err  error
}

// Error implements the error interface.
func (e *HandshakeError) Error() string {
	return "ssh/session: handshake " + e.User + "@" + e.Host + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *HandshakeError) Unwrap() error { return e.Err }

// TimeoutError is returned when Dial or a session operation exceeds
// its context deadline.
type TimeoutError struct {
	Host     string
	Duration time.Duration
	Err      error
}

// Error implements the error interface.
func (e *TimeoutError) Error() string {
	return "ssh/session: timeout on " + e.Host + ": " + e.Duration.String()
}

// Unwrap returns the underlying context error.
func (e *TimeoutError) Unwrap() error { return e.Err }

// CommandError is returned when a remote command exits with a non-zero
// status. ExitCode is -1 when the SSH layer could not recover it (e.g.,
// connection closed mid-command).
type CommandError struct {
	Command  string
	ExitCode int
	Stderr   string
	Err      error
}

// Error implements the error interface.
func (e *CommandError) Error() string {
	if e.Stderr != "" {
		return "ssh/session: command failed: " + e.Command + ": " + e.Stderr
	}
	return "ssh/session: command failed: " + e.Command
}

// Unwrap returns the underlying error.
func (e *CommandError) Unwrap() error { return e.Err }

// SessionError wraps a failure to open a new SSH session channel.
type SessionError struct {
	Host string
	Err  error
}

// Error implements the error interface.
func (e *SessionError) Error() string {
	return "ssh/session: open session on " + e.Host + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *SessionError) Unwrap() error { return e.Err }

// UploadError is returned when streaming an upload fails before the
// remote command completes — for example, the local reader errored mid
// stream or the stdin pipe could not be flushed. A non-zero remote exit
// surfaces a CommandError instead; a cancelled context surfaces a
// TimeoutError.
type UploadError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *UploadError) Error() string {
	return "ssh/session: upload to " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *UploadError) Unwrap() error { return e.Err }

// UnsafePathError is returned when a remote path cannot be safely embedded
// in a single-quoted remote shell argument (e.g., it contains a
// single-quote character). Upload fails closed rather than attempt fragile
// escaping.
type UnsafePathError struct {
	Path   string
	Reason string
}

// Error implements the error interface.
func (e *UnsafePathError) Error() string {
	return "ssh/session: unsafe remote path " + e.Path + ": " + e.Reason
}

// ClosedError is returned by Session methods called after Close has
// completed.
type ClosedError struct{}

// Error implements the error interface.
func (e *ClosedError) Error() string { return "ssh/session: session is closed" }
