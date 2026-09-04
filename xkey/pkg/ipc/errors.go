// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ipc

import "errors"

var (
	// ErrServerClosed is returned when an operation is attempted on a closed server.
	ErrServerClosed = errors.New("ipc: server is closed")

	// ErrClientClosed is returned when an operation is attempted on a closed client.
	ErrClientClosed = errors.New("ipc: client is closed")

	// ErrConnectionFailed is returned when a connection to the IPC socket fails.
	ErrConnectionFailed = errors.New("ipc: connection failed")

	// ErrDaemonNotRunning is returned when the daemon socket does not exist or
	// the connection is refused.
	ErrDaemonNotRunning = errors.New("ipc: daemon is not running")

	// ErrInvalidMessage is returned when a received message fails validation.
	ErrInvalidMessage = errors.New("ipc: invalid message")

	// ErrProtocolError is returned when the wire protocol is violated (e.g.,
	// malformed JSON).
	ErrProtocolError = errors.New("ipc: protocol error")

	// ErrSocketCreateFailed is returned when socket creation fails.
	ErrSocketCreateFailed = errors.New("ipc: socket creation failed")

	// ErrSocketPermission is returned when socket permission operations fail.
	ErrSocketPermission = errors.New("ipc: socket permission error")

	// ErrHandlerFailed is returned when a handler returns an error while
	// processing a message.
	ErrHandlerFailed = errors.New("ipc: handler returned error")

	// ErrTimeout is returned when an IPC operation exceeds its deadline.
	ErrTimeout = errors.New("ipc: operation timed out")

	// ErrUnlockRefused is returned when an unlock handler refuses the unlock
	// without naming a reason.
	ErrUnlockRefused = errors.New("ipc: unlock refused")

	// ErrUnlockNoResult is returned when an unlock handler produces neither a
	// result nor an error. Absence of a result is not success.
	ErrUnlockNoResult = errors.New("ipc: unlock handler returned no result")

	// ErrBarrierSealed is returned when a PKCS#11 operation is attempted
	// while the barrier is sealed.
	ErrBarrierSealed = errors.New("ipc: barrier is sealed")

	// ErrPKCS11Operation is returned when a PKCS#11 operation fails.
	ErrPKCS11Operation = errors.New("ipc: pkcs11 operation failed")

	// ErrAutofillOperation is returned when an autofill operation fails.
	ErrAutofillOperation = errors.New("ipc: autofill operation failed")

	// ErrAutofillDisabled is returned when autofill is requested but the
	// browser extension feature is disabled.
	ErrAutofillDisabled = errors.New("ipc: browser extension is disabled")
)

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
