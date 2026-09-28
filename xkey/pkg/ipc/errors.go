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

	// ErrStateUnsupported is returned when a daemon is running and reachable
	// but does not serve live-state queries. Callers distinguish it from
	// ErrDaemonNotRunning so they can fall back to on-disk state and name
	// the reason, rather than presenting a stale answer as the live one.
	ErrStateUnsupported = errors.New("ipc: daemon does not report live state")

	// ErrStateOperation is returned when a live-state query fails inside the
	// daemon.
	ErrStateOperation = errors.New("ipc: state query failed")

	// ErrSocketPathUnresolved is returned when no per-user socket location
	// can be determined: XKEY_IPC_SOCKET, XKEY_HOME and XDG_RUNTIME_DIR are
	// unset and the user's home directory cannot be resolved. xkey never
	// falls back to a shared directory such as /tmp.
	ErrSocketPathUnresolved = errors.New("ipc: no per-user socket location (set XKEY_IPC_SOCKET, XDG_RUNTIME_DIR or HOME)")

	// ErrSocketDirInsecure is returned when the socket directory is a
	// symbolic link, is not a directory, is owned by an untrusted user, or
	// has any permission bits other than 0700. A directory another user can
	// create or enter lets that user plant a listener that receives this
	// user's PIN, so both the server and the client refuse it.
	ErrSocketDirInsecure = errors.New("ipc: socket directory is not private to this user")

	// ErrSocketInUse is returned by NewServer when a live server already
	// listens on the socket path.
	ErrSocketInUse = errors.New("ipc: another IPC server is already listening")

	// ErrSocketNotOwned is returned by ReclaimSocket when the file at the
	// socket path is not a socket owned by a trusted user.
	ErrSocketNotOwned = errors.New("ipc: socket file is not a socket owned by this user")

	// ErrPeerUntrusted is returned when the process at the other end of the
	// socket runs as a user other than this user, root, or the sudo user.
	ErrPeerUntrusted = errors.New("ipc: socket peer is not a trusted user")

	// ErrPeerCredentials is returned when the kernel's record of the socket
	// peer's credentials cannot be read.
	ErrPeerCredentials = errors.New("ipc: cannot read socket peer credentials")

	// ErrPeerCredentialsUnsupported is returned on platforms that expose no
	// peer-credential API that xkey uses (anything other than Linux, macOS
	// and FreeBSD). The client refuses to connect rather than send a PIN to
	// an unverified peer.
	ErrPeerCredentialsUnsupported = errors.New("ipc: socket peer credential verification is not supported on this platform")
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
