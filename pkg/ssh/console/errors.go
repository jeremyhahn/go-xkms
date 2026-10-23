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

// DialError wraps a failure to connect to the remote host or to complete the
// SSH handshake with it. Under GODEBUG=fips140=only crypto/ecdh refuses the
// X25519 computation the curve25519-sha256 key exchange needs; Err carries
// that refusal unchanged, so
// errors.Is and errors.As still reach it.
type DialError struct {
	Host string
	Err  error
}

func (e *DialError) Error() string { return "ssh/console: dial " + e.Host + ": " + e.Err.Error() }
func (e *DialError) Unwrap() error { return e.Err }

// ClosedError indicates an operation on a closed console.
type ClosedError struct{}

func (e *ClosedError) Error() string { return "ssh/console: console is closed" }

// WriteClosedError indicates a Write after CloseWrite: the console's write
// half has been shut and the remote has already seen EOF on its stdin.
type WriteClosedError struct{}

func (e *WriteClosedError) Error() string { return "ssh/console: write half is closed" }

// UpgradeRefusedError indicates the WebSocket handshake could not be answered
// because the standard library refused SHA-1, which RFC 6455 §4.2.2 requires
// for the Sec-WebSocket-Accept header. Under GODEBUG=fips140=only the Go
// Cryptographic Module refuses SHA-1; Err is that refusal.
type UpgradeRefusedError struct {
	Err error
}

func (e *UpgradeRefusedError) Error() string {
	return "ssh/console: websocket upgrade refused: " + e.Err.Error()
}
func (e *UpgradeRefusedError) Unwrap() error { return e.Err }

// Is matches any *UpgradeRefusedError, so errors.Is(err, &UpgradeRefusedError{})
// reports a refused upgrade whatever its cause.
func (e *UpgradeRefusedError) Is(target error) bool {
	_, ok := target.(*UpgradeRefusedError)
	return ok
}
